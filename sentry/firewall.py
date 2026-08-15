"""Firewall posture and inbound connections — who can reach in, and who did.

Outbound egress is covered by the process scanner. This module looks the other
way down the wire:

  * the firewall's actual state, per profile, including whether logging is on
  * every inbound Allow rule, with attention to the dangerous shapes: any
    program, any remote address, or a rule pointing at a user-writable path
  * connections that were initiated *from outside* — distinguished from your own
    outbound traffic by whether the local port is one you are listening on
  * remote logons and file-share sessions, which is what an actual intrusion
    looks like after the connection succeeds
"""

import re

from .collect_linux import _read, _socket_table
from .control import REMOTE_AGENTS, _aslist, _ps_json
from .util import classify_ip

USER_WRITABLE = re.compile(r"\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\|"
                           r"\\programdata\\", re.I)

# Rule groups that hand out interactive control or file access. These are worth
# surfacing even though Windows ships them, because whether they are *on* is a
# decision, not a default.
NOTABLE_GROUPS = re.compile(
    r"remote desktop|remote assistance|remote event|remote service|"
    r"remote volume|remote scheduled|windows remote management|winrm|"
    r"file and printer sharing|netlogon|windows management instrumentation",
    re.I,
)


def _finding(category, severity, title, detail, where="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


# ---------------------------------------------------------------------------
# Linux side: who is listening, and who connected in
# ---------------------------------------------------------------------------

def audit_linux():
    out = []
    table = _socket_table()

    listening = {c["local_port"] for c in table.values() if c["state"] == "LISTEN"}
    for conn in table.values():
        if conn["state"] != "ESTABLISHED":
            continue
        # An established connection on a port we listen on came from outside.
        if conn["local_port"] in listening:
            scope = classify_ip(conn["remote_ip"])
            if scope in ("loopback",):
                continue
            sev = "critical" if scope == "public" else "medium"
            out.append(_finding(
                "inbound", sev, "inbound connection from outside",
                f"{conn['remote_ip']}:{conn['remote_port']} → local port "
                f"{conn['local_port']} ({scope})",
                "/proc/net", host="wsl"))

    # WSL's own firewall state is mostly advisory — Windows filters the NAT — but
    # a local rule set that blocks nothing is still worth stating plainly.
    nft = _read("/proc/net/nf_conntrack")
    if not _read("/proc/net/ip_tables_names").strip() and not nft:
        out.append(_finding("posture", "low", "no netfilter rules loaded in WSL",
                            "the Windows host firewall is what actually protects "
                            "this machine's network edge", "/proc/net", host="wsl"))
    return out


# ---------------------------------------------------------------------------
# Windows side
# ---------------------------------------------------------------------------

PS_FW = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.profiles = @(Get-NetFirewallProfile | ForEach-Object {
  [pscustomobject]@{
    name=$_.Name; enabled=[bool]$_.Enabled
    inbound=[string]$_.DefaultInboundAction; outbound=[string]$_.DefaultOutboundAction
    logBlocked=[bool]$_.LogBlocked; logAllowed=[bool]$_.LogAllowed
    logFile=[string]$_.LogFileName; notify=[string]$_.NotifyOnListen
  } })

# Inbound Allow rules, joined to their program/address/port filters.
# Piping each rule into Get-NetFirewall*Filter individually is an N+1 query that
# takes minutes on a normal rule set, so the filters are fetched in bulk once and
# joined on InstanceID (which equals the rule's Name).
$appF  = @{}; Get-NetFirewallApplicationFilter | ForEach-Object { $appF[$_.InstanceID]  = [string]$_.Program }
$addrF = @{}; Get-NetFirewallAddressFilter     | ForEach-Object { $addrF[$_.InstanceID] = [string]($_.RemoteAddress -join ',') }
$portF = @{}; Get-NetFirewallPortFilter        | ForEach-Object { $portF[$_.InstanceID] = "$($_.Protocol)/$($_.LocalPort -join ',')" }

$o.rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  ForEach-Object {
    [pscustomobject]@{
      name    = $_.DisplayName
      group   = [string]$_.DisplayGroup
      profile = [string]$_.Profile
      app     = [string]$appF[$_.Name]
      remote  = [string]$addrF[$_.Name]
      port    = [string]$portF[$_.Name]
      owner   = [string]$_.Owner
      # A rule whose program is gone is a pre-approved hole waiting for anything
      # that lands on that exact path. Windows' own rules name the pseudo-program
      # "System" or embed %SystemRoot%-style variables, so both have to be
      # handled before a missing file means anything.
      exists  = $(
                  $a = [string]$appF[$_.Name]
                  if (-not $a -or $a -eq 'Any' -or $a -eq 'System') { $true }
                  else {
                    $x = [Environment]::ExpandEnvironmentVariables($a)
                    [bool](Test-Path -LiteralPath $x)
                  })
    } })

$o.conns = @(Get-NetTCPConnection | ForEach-Object {
  [pscustomobject]@{ state=[string]$_.State; lip=$_.LocalAddress; lport=$_.LocalPort
                     rip=$_.RemoteAddress; rport=$_.RemotePort; pid=$_.OwningProcess
                     created=if($_.CreationTime){$_.CreationTime.ToString('o')}else{''} } })

$o.procs = @(Get-CimInstance Win32_Process |
  ForEach-Object { [pscustomobject]@{ pid=$_.ProcessId; name=$_.Name; path=$_.ExecutablePath } })

# Who is connected to this machine's file shares right now.
$o.smb = @(Get-SmbSession | ForEach-Object {
  [pscustomobject]@{ client=[string]$_.ClientComputerName; user=[string]$_.ClientUserName
                     numOpen=$_.NumOpens } })

# Remote logons. The Security log usually needs elevation; the flag tells the
# report whether an empty result means "none" or "not allowed to look".
$o.secReadable = $false
$sec = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200
if ($sec) { $o.secReadable = $true }
$o.logons = @($sec | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ time=$_.TimeCreated.ToString('o'); type=$d['LogonType']
                       user=$d['TargetUserName']; ip=$d['IpAddress']
                       proc=$d['ProcessName'] } } |
  Where-Object { $_.type -in @('3','10') -and $_.ip -and $_.ip -ne '-' -and $_.ip -ne '127.0.0.1' })

$fail = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200
$o.failed = @($fail | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ time=$_.TimeCreated.ToString('o'); user=$d['TargetUserName']
                       ip=$d['IpAddress'] } } |
  Where-Object { $_.ip -and $_.ip -ne '-' })

# A service installed recently is how most remote-access footholds land.
$o.newsvc = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045;
                StartTime=(Get-Date).AddDays(-30)} -MaxEvents 40 |
  ForEach-Object { [pscustomobject]@{ time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def audit_windows():
    data = _ps_json(PS_FW, timeout=240)
    if data is None:
        return [_finding("posture", "medium", "firewall audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- posture -----------------------------------------------------------
    for p in _aslist(data.get("profiles")):
        nm = p.get("name")
        if not p.get("enabled"):
            out.append(_finding("posture", "critical",
                                f"firewall OFF on the {nm} profile",
                                "inbound traffic is unfiltered on this network type",
                                "Get-NetFirewallProfile"))
        if (p.get("inbound") or "").lower() == "allow":
            out.append(_finding("posture", "critical",
                                f"{nm} profile allows inbound by default",
                                "anything not explicitly blocked can reach this machine",
                                "DefaultInboundAction"))
        if not p.get("logBlocked"):
            out.append(_finding("posture", "low",
                                f"{nm} profile does not log blocked connections",
                                "turning this on gives you a record of what got "
                                "turned away", p.get("logFile") or ""))

    # -- inbound allow rules ----------------------------------------------
    rules = _aslist(data.get("rules"))
    for r in rules:
        app = r.get("app") or ""
        remote = r.get("remote") or "Any"
        name = r.get("name") or "?"
        group = r.get("group") or ""

        # A grouped rule shipped with Windows or with a feature you turned on.
        # Reporting every one of those buries the rules something *added*, so
        # stock groups are skipped unless the group itself grants remote control
        # or the program sits somewhere anyone could have replaced it.
        if (group and not NOTABLE_GROUPS.search(group)
                and not USER_WRITABLE.search(app) and r.get("exists") is not False):
            continue

        risky = []
        if app and app != "Any" and r.get("exists") is False:
            risky.append("program no longer installed — orphaned rule")
        if app in ("", "Any", None) and not group:
            risky.append("any program")
        if remote in ("Any", "*", ""):
            risky.append("any remote address")
        if USER_WRITABLE.search(app):
            risky.append("program in a user-writable directory")
        if NOTABLE_GROUPS.search(group):
            risky.append(f"grants remote access ({group})")

        # A firewall hole opened for a remote-control agent is the single most
        # consequential rule shape here: it means something can be driven from
        # outside, by design.
        agent = REMOTE_AGENTS.search(f"{name} {app}")
        if agent:
            risky.append("REMOTE-CONTROL AGENT")

        if not risky:
            continue
        if agent:
            sev = "critical"
        elif ("program in a user-writable directory" in risky or len(risky) > 1):
            sev = "high"
        else:
            sev = "medium"
        out.append(_finding(
            "rules", sev, "permissive inbound rule",
            f"{name} — {', '.join(risky)}"
            + (f" [{r.get('port')}]" if r.get("port") else ""),
            app or r.get("group") or ""))

    out.append(_finding("rules", "ok", "inbound allow rules",
                        f"{len(rules)} enabled", "Get-NetFirewallRule"))

    # -- inbound connections ----------------------------------------------
    conns = _aslist(data.get("conns"))
    procs = {p.get("pid"): p for p in _aslist(data.get("procs"))}
    listening = {c.get("lport") for c in conns if c.get("state") == "Listen"}

    for c in conns:
        if c.get("state") != "Established":
            continue
        if c.get("lport") not in listening:
            continue  # our own outbound socket, not someone reaching in
        rip = c.get("rip") or ""
        scope = classify_ip(rip)
        if scope in ("loopback", "unspecified", "invalid"):
            continue
        who = procs.get(c.get("pid"), {})
        sev = "critical" if scope == "public" else "medium"
        out.append(_finding(
            "inbound", sev, "inbound connection from outside",
            f"{rip}:{c.get('rport')} → local port {c.get('lport')} ({scope}) "
            f"served by {who.get('name') or f'pid {c.get('pid')}'}",
            (who.get("path") or "") + (f"  since {c.get('created')}"
                                       if c.get("created") else "")))

    # -- who actually logged in remotely ----------------------------------
    logons = _aslist(data.get("logons"))
    for l in logons:
        kind = "RDP" if str(l.get("type")) == "10" else "network"
        scope = classify_ip(l.get("ip") or "")
        sev = "critical" if scope == "public" else "high"
        out.append(_finding("access", sev, f"remote {kind} logon succeeded",
                            f"{l.get('user')} from {l.get('ip')} ({scope})",
                            l.get("time") or ""))

    failed = _aslist(data.get("failed"))
    if failed:
        by_ip = {}
        for f in failed:
            by_ip.setdefault(f.get("ip"), []).append(f)
        for ip, items in sorted(by_ip.items(), key=lambda kv: -len(kv[1]))[:10]:
            scope = classify_ip(ip or "")
            sev = "high" if len(items) >= 10 or scope == "public" else "medium"
            out.append(_finding("access", sev, "failed logon attempts",
                                f"{len(items)} failures from {ip} ({scope}), "
                                f"latest user tried: {items[0].get('user')}",
                                items[0].get("time") or ""))

    if not data.get("secReadable"):
        out.append(_finding("access", "medium", "security log not readable",
                            "remote-logon history needs an elevated PowerShell — "
                            "an empty result here does not mean nobody logged in",
                            "Security event log"))

    for s in _aslist(data.get("smb")):
        out.append(_finding("access", "high", "active file-share session",
                            f"{s.get('client')} as {s.get('user')} "
                            f"({s.get('numOpen')} files open)", "Get-SmbSession"))

    # Event 7045's message is one run-on string once newlines are stripped, so
    # each field has to be bounded by the label that follows it. The same
    # service reinstalls on every update, so collapse repeats into a count.
    installs = {}
    for s in _aslist(data.get("newsvc")):
        msg = s.get("msg") or ""
        name = re.search(r"Service Name:\s*(.*?)\s*Service File Name:", msg)
        file = re.search(r"Service File Name:\s*(.*?)\s*Service Type:", msg)
        key = (name.group(1) if name else msg[:60]).strip()
        entry = installs.setdefault(key, {"n": 0, "file": "", "last": ""})
        entry["n"] += 1
        entry["file"] = entry["file"] or (file.group(1).strip() if file else "")
        entry["last"] = max(entry["last"], s.get("time") or "")

    for name, e in sorted(installs.items(), key=lambda kv: kv[1]["last"], reverse=True):
        sev = "high" if USER_WRITABLE.search(e["file"]) else "medium"
        times = f" ×{e['n']}" if e["n"] > 1 else ""
        out.append(_finding("posture", sev, "service installed recently",
                            f"{name}{times} — {e['file'][:90] or 'path unknown'}",
                            e["last"].replace("T", " ")[:19]))

    return out


CAT_ORDER = {"inbound": 0, "access": 1, "posture": 2, "rules": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += audit_linux()
    if "win" in hosts:
        out += audit_windows()
    out.sort(key=lambda f: (CAT_ORDER.get(f["category"], 9),
                            SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out
