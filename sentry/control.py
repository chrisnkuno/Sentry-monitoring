"""Audit the ways something can take or keep control of the machine.

Process monitoring answers "what is running right now". This module answers the
harder question: "what has arranged to run later, what can drive this machine
from outside, and has anything turned off the defenses?"

Three categories:
  persistence -- autostart hooks that survive reboot (tasks, services, cron,
                 registry Run keys, shell rc files, authorized_keys)
  remote      -- anything that grants interactive control from elsewhere
                 (RDP, WinRM, SSH, VNC/TeamViewer/AnyDesk-class agents)
  defense     -- the state of the controls themselves (Defender, tamper
                 protection, firewall, audit logging), because an attacker's
                 first move is usually to disable them
"""

import base64
import glob
import json
import os
import re
import subprocess

from . import collect_windows
from .util import short

# Commercial remote-control agents. Presence is not proof of compromise -- it is
# proof that someone can drive this machine, which is what you asked to see.
REMOTE_AGENTS = re.compile(
    r"teamviewer|anydesk|rustdesk|ultravnc|tightvnc|realvnc|vncserver|x11vnc|"
    r"screenconnect|connectwise|logmein|gotoassist|splashtop|supremo|ammyy|"
    r"radmin|dwservice|dwagent|atera|ninjarmm|ninjaone|syncro|kaseya|"
    r"chrome remote desktop|remotepc|zoho assist|action1|pulseway|"
    r"quickassist|mstsc|psexec|paexec|meshagent|tacticalrmm",
    re.I,
)

# PowerShell's -EncodedCommand, as a real flag rather than any string containing
# "enc" (Proton's "ms-encodedlaunch:" URI matched a looser pattern).
OBFUSCATED = re.compile(
    r"(?:^|[\s\"'])[-/]e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{30,}|"
    r"FromBase64String|"
    r"powershell[^\n]*\s[-/]w(?:indowstyle)?\s+hidden",
    re.I,
)


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True,
                           errors="replace")
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": ""}


# ---------------------------------------------------------------------------
# Linux / WSL side
# ---------------------------------------------------------------------------

SHELL_RC = ["~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc",
            "~/.bash_login", "~/.config/autostart"]


def audit_linux():
    out = []

    # -- persistence: cron -------------------------------------------------
    crontab = _run(["crontab", "-l"])
    for line in crontab.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(_finding("persistence", "medium", "user cron job",
                                short(line, 100), "crontab -l"))

    for path in glob.glob("/etc/cron.d/*") + ["/etc/crontab"]:
        try:
            with open(path, errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("SHELL") \
                            and not line.startswith("PATH") and not line.startswith("MAILTO"):
                        out.append(_finding("persistence", "low", "system cron entry",
                                            short(line, 100), path))
        except OSError:
            pass

    # -- persistence: systemd ---------------------------------------------
    units = _run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager",
                  "--no-legend"])
    for line in units.splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit and not unit.startswith(("systemd-", "dbus", "getty", "network",
                                         "ssh.socket", "cron")):
            out.append(_finding("persistence", "low", "enabled systemd unit", unit,
                                "systemctl"))

    for pattern in ("/etc/systemd/system/*.service", os.path.expanduser(
            "~/.config/systemd/user/*.service")):
        for path in glob.glob(pattern):
            out.append(_finding("persistence", "medium", "custom systemd service",
                                os.path.basename(path), path))

    # -- persistence: shell startup + rc hooks -----------------------------
    for rc in SHELL_RC:
        path = os.path.expanduser(rc)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    s = line.strip()
                    if re.search(r"(curl|wget)\s+[^|]*\|\s*(ba)?sh|nc\s+-e|"
                                 r"base64\s+-d|/dev/tcp/", s):
                        out.append(_finding("persistence", "critical",
                                            "shell rc runs remote code",
                                            short(s, 100), f"{path}:{n}"))
        except OSError:
            pass

    # -- persistence: preload hijack ---------------------------------------
    if os.path.exists("/etc/ld.so.preload"):
        try:
            with open("/etc/ld.so.preload", errors="replace") as fh:
                body = fh.read().strip()
        except OSError:
            body = "<unreadable>"
        if body:
            out.append(_finding("persistence", "critical",
                                "global library preload set", body,
                                "/etc/ld.so.preload"))

    # -- remote: SSH trust -------------------------------------------------
    for path in glob.glob(os.path.expanduser("~/.ssh/authorized_keys")) + \
            glob.glob("/home/*/.ssh/authorized_keys") + \
            glob.glob("/root/.ssh/authorized_keys"):
        try:
            with open(path, errors="replace") as fh:
                keys = [l for l in fh if l.strip() and not l.startswith("#")]
        except OSError:
            continue
        for k in keys:
            comment = k.strip().split()[-1] if len(k.split()) > 2 else "(no comment)"
            out.append(_finding("remote", "high", "SSH key can log in as this user",
                                comment, path))

    # -- remote: listening services ---------------------------------------
    ss = _run(["ss", "-tulnp"])
    for line in ss.splitlines()[1:]:
        f = line.split()
        if len(f) < 5:
            continue
        local = f[4]
        if local.startswith(("0.0.0.0", "*", "[::]", ":::")):
            proc = f[6] if len(f) > 6 else ""
            sev = "high" if REMOTE_AGENTS.search(line) else "medium"
            out.append(_finding("remote", sev, "listening on all interfaces",
                                f"{local} {short(proc, 60)}", "ss -tulnp"))

    # -- privilege: sudoers drop-ins --------------------------------------
    for path in glob.glob("/etc/sudoers.d/*"):
        try:
            with open(path, errors="replace") as fh:
                body = fh.read()
        except OSError:
            continue
        if "NOPASSWD" in body:
            out.append(_finding("defense", "high", "passwordless sudo rule",
                                short(body.strip().replace("\n", " "), 90), path))

    # -- defense: WSL is not the security boundary -------------------------
    if os.path.exists("/mnt/c/Windows"):
        out.append(_finding("defense", "low", "Windows drive mounted in WSL",
                            "processes in WSL can read and write the Windows "
                            "filesystem at /mnt/c", "/mnt/c"))

    for f in out:
        f["host"] = "wsl"
    return out


# ---------------------------------------------------------------------------
# Windows side
# ---------------------------------------------------------------------------

PS_CONTROL = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- persistence: scheduled tasks not shipped by Microsoft
$o.tasks = @(Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
} | ForEach-Object {
    $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
    [pscustomobject]@{ name=$_.TaskName; path=$_.TaskPath; author=$_.Author; action=$a }
})

# --- persistence: Run / RunOnce registry keys
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$o.runkeys = @(foreach ($k in $runKeys) {
    $p = Get-ItemProperty -Path $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object { [pscustomobject]@{ key=$k; name=$_.Name; value=[string]$_.Value } } }
})

# --- persistence: startup folders
$o.startup = @(Get-ChildItem -Path @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") -File |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; path=$_.FullName } })

# --- persistence: auto-start services outside system32
$o.services = @(Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -and
                   $_.PathName -notlike '*\System32\*' } |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; disp=$_.DisplayName;
                                        path=$_.PathName; state=$_.State } })

# --- persistence: WMI event subscriptions (a quiet, classic foothold)
$o.wmi = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    ForEach-Object { [pscustomobject]@{ filter=[string]$_.Filter; consumer=[string]$_.Consumer } })

# --- remote: inbound control channels
$rdpDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$winrm   = (Get-Service WinRM).Status
$sshd    = (Get-Service sshd).Status
$o.remote = [pscustomobject]@{
    rdpEnabled = ($rdpDeny -eq 0)
    winrm      = [string]$winrm
    sshd       = [string]$sshd
    sessions   = @(query user 2>$null)
}

# --- remote: interactive logon sessions other than the console
$o.logons = @(Get-CimInstance Win32_LogonSession |
    Where-Object { $_.LogonType -in 3,10 } |
    Select-Object -First 20 LogonId, LogonType, StartTime)

# --- defense: Defender + tamper protection
$mp = Get-MpComputerStatus
$pref = Get-MpPreference
$o.defender = [pscustomobject]@{
    present          = [bool]$mp
    realtime         = $mp.RealTimeProtectionEnabled
    tamperProtection = $mp.IsTamperProtected
    antivirus        = $mp.AntivirusEnabled
    sigAgeDays       = $mp.AntivirusSignatureAge
    exclusionPaths   = @($pref.ExclusionPath)
    exclusionProcs   = @($pref.ExclusionProcess)
}

# --- defense: firewall profile state
$o.firewall = @(Get-NetFirewallProfile |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; enabled=$_.Enabled } })

# --- defense: inbound Allow rules opened for specific programs
$o.fwrules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Where-Object { $_.Group -eq $null -or $_.Group -eq '' } |
    Select-Object -First 40 DisplayName, Profile)

# --- privilege: who is a local administrator
$o.admins = @((Get-LocalGroupMember -Group 'Administrators').Name)

# --- privilege: UAC posture
$o.uac = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def _ps_json(script, timeout=120):
    """Run a PowerShell script and decode its base64 JSON payload.

    Retries once after forcing interop re-resolution: the socket named in
    WSL_INTEROP can go stale between calls when the session that created it
    ends, and the only symptom is empty output.
    """
    if not collect_windows.available():
        return None

    for attempt in (1, 2):
        try:
            r = subprocess.run(
                [collect_windows._PS, "-NoProfile", "-NonInteractive",
                 "-Command", script],
                capture_output=True, timeout=timeout, cwd="/",
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

        blob = (r.stdout.decode("ascii", "ignore")
                .strip().replace("\r", "").replace("\n", ""))
        if blob:
            try:
                return json.loads(base64.b64decode(blob).decode("utf-8", "replace"))
            except Exception:
                return None

        if attempt == 1:
            # No output at all: most likely a dead interop socket. Drop the
            # cached value so ensure_interop() picks a fresh one, and retry.
            os.environ.pop("WSL_INTEROP", None)
            if not collect_windows.ensure_interop():
                return None
    return None


def _aslist(v):
    """PowerShell collapses single-element arrays; normalize back to a list."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def audit_windows():
    data = _ps_json(PS_CONTROL)
    if data is None:
        return [_finding("defense", "medium", "Windows audit unavailable",
                         "powershell.exe did not return data; some checks need an "
                         "elevated shell", "interop")]
    out = []

    for t in _aslist(data.get("tasks")):
        action = t.get("action") or ""
        sev = "high" if REMOTE_AGENTS.search(action + (t.get("name") or "")) else "low"
        if OBFUSCATED.search(action):
            sev = "critical"
        out.append(_finding("persistence", sev, "scheduled task",
                            f"{t.get('name')} → {short(action, 90)}",
                            (t.get("path") or "") + str(t.get("name"))))

    for k in _aslist(data.get("runkeys")):
        val = k.get("value") or ""
        sev = "high" if REMOTE_AGENTS.search(val) else "medium"
        if OBFUSCATED.search(val) or re.search(r"\\temp\\|\\downloads\\", val, re.I):
            sev = "critical"
        out.append(_finding("persistence", sev, "autostart registry entry",
                            f"{k.get('name')} = {short(val, 90)}", k.get("key", "")))

    for s in _aslist(data.get("startup")):
        out.append(_finding("persistence", "medium", "startup folder item",
                            s.get("name", ""), s.get("path", "")))

    for s in _aslist(data.get("services")):
        path = s.get("path") or ""
        sev = "high" if REMOTE_AGENTS.search(path + (s.get("disp") or "")) else "low"
        if re.search(r"\\temp\\|\\users\\public\\|\\appdata\\", path, re.I):
            sev = "critical"
        out.append(_finding("persistence", sev, "auto-start service",
                            f"{s.get('disp') or s.get('name')} [{s.get('state')}] "
                            f"{short(path, 80)}", s.get("name", "")))

    for w in _aslist(data.get("wmi")):
        pair = f"{w.get('filter')} {w.get('consumer')}"
        # Windows ships one of these out of the box; the rest deserve alarm.
        stock = "SCM Event Log" in pair
        out.append(_finding("persistence", "low" if stock else "critical",
                            "WMI event subscription"
                            + (" (Windows built-in)" if stock else ""),
                            f"{short(str(w.get('filter')), 60)} → "
                            f"{short(str(w.get('consumer')), 60)}",
                            "root\\subscription"))

    remote = data.get("remote") or {}
    if remote.get("rdpEnabled"):
        out.append(_finding("remote", "high", "Remote Desktop is enabled",
                            "inbound RDP can drive this machine interactively",
                            "Terminal Server\\fDenyTSConnections"))
    if (remote.get("winrm") or "") == "Running":
        out.append(_finding("remote", "high", "WinRM service running",
                            "accepts remote PowerShell", "Service: WinRM"))
    if (remote.get("sshd") or "") == "Running":
        out.append(_finding("remote", "high", "OpenSSH server running",
                            "accepts inbound SSH", "Service: sshd"))
    for line in _aslist(remote.get("sessions")):
        if isinstance(line, str) and line.strip() and "USERNAME" not in line:
            out.append(_finding("remote", "medium", "logon session",
                                short(line.strip(), 90), "query user"))

    d = data.get("defender") or {}
    if d.get("present"):
        if d.get("realtime") is False:
            out.append(_finding("defense", "critical",
                                "Defender real-time protection is OFF",
                                "live scanning disabled", "Get-MpComputerStatus"))
        if d.get("tamperProtection") is False:
            out.append(_finding("defense", "high", "Tamper Protection is OFF",
                                "Defender settings can be changed by software",
                                "Get-MpComputerStatus"))
        if d.get("antivirus") is False:
            out.append(_finding("defense", "critical", "Defender antivirus disabled",
                                "", "Get-MpComputerStatus"))
        age = d.get("sigAgeDays")
        if isinstance(age, int) and age > 7:
            out.append(_finding("defense", "medium", "Defender signatures stale",
                                f"{age} days old", "Get-MpComputerStatus"))
        denied = False
        for kind, key in (("path", "exclusionPaths"), ("process", "exclusionProcs")):
            for p in _aslist(d.get(key)):
                if not p:
                    continue
                if str(p).startswith("N/A"):
                    denied = True  # non-admin shell: value is a refusal, not a path
                    continue
                out.append(_finding("defense", "high",
                                    f"Defender scan exclusion ({kind})",
                                    str(p), "Get-MpPreference"))
        if denied:
            out.append(_finding("defense", "medium", "Defender exclusions not readable",
                                "run this audit from an elevated PowerShell to see "
                                "which paths are excluded from scanning",
                                "Get-MpPreference"))
    else:
        out.append(_finding("defense", "medium", "Defender status unreadable",
                            "run the audit from an elevated shell for defense checks",
                            "Get-MpComputerStatus"))

    for fw in _aslist(data.get("firewall")):
        if fw.get("enabled") in (False, 0, "False"):
            out.append(_finding("defense", "critical",
                                f"firewall disabled on {fw.get('name')} profile",
                                "inbound traffic unfiltered", "Get-NetFirewallProfile"))

    for r in _aslist(data.get("fwrules")):
        out.append(_finding("remote", "low", "inbound firewall allow rule",
                            short(str(r.get("DisplayName")), 80),
                            str(r.get("Profile"))))

    for a in _aslist(data.get("admins")):
        out.append(_finding("defense", "low", "local administrator", str(a),
                            "Administrators group"))

    if data.get("uac") == 0:
        out.append(_finding("defense", "critical", "UAC is disabled",
                            "elevation prompts are off", "EnableLUA"))

    for f in out:
        f["host"] = "win"
    return out


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"defense": 0, "remote": 1, "persistence": 2}


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += audit_linux()
    if "win" in hosts:
        out += audit_windows()
    # Group by category first so each section prints once, worst item at the top.
    out.sort(key=lambda f: (CAT_ORDER.get(f["category"], 9),
                            SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out
