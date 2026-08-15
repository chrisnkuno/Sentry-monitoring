"""Autostart Extensibility Points — the persistence surface beyond Run keys.

Run keys and scheduled tasks are where you look first and where commodity
adware stops. Anything trying to stay quiet uses one of the dozens of other
places Windows will load code from, most of which no user ever inspects:

  loader abuse      AppInit_DLLs, Image File Execution Options debuggers,
                    Winsock LSPs -- these inject into other processes rather
                    than starting one of their own
  logon chain       Winlogon Shell/Userinit/Taskman, Active Setup StubPath
  COM hijacking     a per-user CLSID registration silently overrides the
                    machine-wide one, so a normal app loads the attacker's DLL
  service plumbing  LSA packages, print monitors, netsh helpers, time providers
                    -- all load into privileged processes
  accessibility     the sethc.exe / utilman.exe backdoor, reachable from the
                    logon screen before anyone authenticates

It also reads UserAssist, Windows' own record of which GUI programs were
launched and when, and checks running processes for system-binary
masquerading -- a "svchost.exe" that is not in System32 is not svchost.
"""

import re

from .control import _aslist, _ps_json

# Names an implant borrows to blend into a process list. Each one has exactly
# one legitimate home directory.
SYSTEM_BINARIES = {
    "svchost.exe": r"\\windows\\system32\\|\\windows\\syswow64\\",
    "lsass.exe": r"\\windows\\system32\\",
    "services.exe": r"\\windows\\system32\\",
    "csrss.exe": r"\\windows\\system32\\",
    "winlogon.exe": r"\\windows\\system32\\",
    "smss.exe": r"\\windows\\system32\\",
    "wininit.exe": r"\\windows\\system32\\",
    "spoolsv.exe": r"\\windows\\system32\\",
    "taskhostw.exe": r"\\windows\\system32\\",
    "dllhost.exe": r"\\windows\\system32\\|\\windows\\syswow64\\",
    "rundll32.exe": r"\\windows\\system32\\|\\windows\\syswow64\\",
    "conhost.exe": r"\\windows\\system32\\",
    "explorer.exe": r"\\windows\\",
}

# Parent → child pairs that are normal individually and suspicious together.
BAD_PARENTAGE = [
    (r"^(winword|excel|powerpnt|outlook|msaccess)\.exe$",
     r"^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$",
     "an Office application spawned a script host"),
    (r"^(chrome|firefox|msedge|opera|brave)\.exe$",
     r"^(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$",
     "a browser spawned a script host"),
    (r"^wmiprvse\.exe$", r"^(powershell|pwsh|cmd)\.exe$",
     "WMI spawned a shell — a common lateral-movement path"),
    # lsass and csrss have no business starting anything. winlogon does — it
    # launches the desktop window manager, the font host, userinit and LogonUI —
    # so it is checked against that known set rather than blanket-flagged.
    (r"^(lsass|csrss)\.exe$", r".*",
     "a protected system process has a child"),
    (r"^winlogon\.exe$",
     r"^(?!(dwm|fontdrvhost|userinit|logonui|consent|sihost)\.exe$).*",
     "winlogon started something outside its normal set"),
]


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


PS_ASEP = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

function Get-Val($path, $name) {
  $p = Get-ItemProperty -Path $path -Name $name
  if ($p) { return [string]$p.$name }
  return ''
}

# --- loader abuse ---------------------------------------------------------
$o.appinit = @(foreach ($k in @(
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
  $v = Get-Val $k 'AppInit_DLLs'
  $e = Get-Val $k 'LoadAppInit_DLLs'
  if ($v) { [pscustomobject]@{ key=$k; dlls=$v; enabled=$e } }
})

# Image File Execution Options: a "Debugger" value replaces the program itself.
$o.ifeo = @(Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  ForEach-Object {
    $dbg = Get-Val $_.PSPath 'Debugger'
    $flt = Get-Val $_.PSPath 'GlobalFlag'
    if ($dbg -or $flt -eq '512') {
      [pscustomobject]@{ target=$_.PSChildName; debugger=$dbg; globalFlag=$flt } } })

# --- logon chain ----------------------------------------------------------
$wl = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$o.winlogon = [pscustomobject]@{
  shell    = Get-Val $wl 'Shell'
  userinit = Get-Val $wl 'Userinit'
  taskman  = Get-Val $wl 'Taskman'
  appsetup = Get-Val $wl 'AppSetup'
}

$o.activeSetup = @(Get-ChildItem 'HKLM:\Software\Microsoft\Active Setup\Installed Components' |
  ForEach-Object {
    $sp = Get-Val $_.PSPath 'StubPath'
    if ($sp) { [pscustomobject]@{ key=$_.PSChildName; stub=$sp } } })

# --- COM hijacking --------------------------------------------------------
# A CLSID registered under HKCU wins over the machine-wide one, so a per-user
# InprocServer32 pointing outside Windows is how a normal app is made to load
# somebody else's DLL.
function Resolve-Dll([string]$dll) {
  if (-not $dll) { return $null }
  $p = [Environment]::ExpandEnvironmentVariables($dll.Trim('"'))
  # A bare name resolves out of System32 at load time.
  if ($p -notmatch '[\\/]') { $p = Join-Path $env:SystemRoot "System32\$p" }
  return [pscustomobject]@{ path=$p; exists=[bool](Test-Path -LiteralPath $p) }
}

$o.comHijack = @(Get-ChildItem 'HKCU:\Software\Classes\CLSID' |
  ForEach-Object {
    $ip = Join-Path $_.PSPath 'InprocServer32'
    if (Test-Path $ip) {
      $dll = [string](Get-ItemProperty $ip).'(default)'
      if ($dll) {
        $r = Resolve-Dll $dll
        [pscustomobject]@{ clsid=$_.PSChildName; dll=$dll
                           path=$r.path; exists=$r.exists } } } })

# --- privileged plumbing --------------------------------------------------
$lsa = 'HKLM:\System\CurrentControlSet\Control\Lsa'
$o.lsa = [pscustomobject]@{
  security     = [string]((Get-ItemProperty $lsa).'Security Packages' -join ',')
  notification = [string]((Get-ItemProperty $lsa).'Notification Packages' -join ',')
  authentication = [string]((Get-ItemProperty $lsa).'Authentication Packages' -join ',')
}
$o.printMonitors = @(Get-ChildItem 'HKLM:\System\CurrentControlSet\Control\Print\Monitors' |
  ForEach-Object { [pscustomobject]@{ name=$_.PSChildName; dll=(Get-Val $_.PSPath 'Driver') } })
$o.netsh = @((Get-Item 'HKLM:\Software\Microsoft\Netsh').Property |
  ForEach-Object { [pscustomobject]@{ name=$_; dll=(Get-Val 'HKLM:\Software\Microsoft\Netsh' $_) } })
$o.timeProviders = @(Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders' |
  ForEach-Object { [pscustomobject]@{ name=$_.PSChildName; dll=(Get-Val $_.PSPath 'DllName')
                                      enabled=(Get-Val $_.PSPath 'Enabled') } })

# --- explorer extension points -------------------------------------------
# Extension points hold CLSIDs, not paths. Resolving each one to the DLL it
# actually loads is what makes the difference between "a hook exists" (always
# true) and "a hook loads code from somewhere it shouldn't".
function Resolve-Clsid([string]$clsid) {
  foreach ($root in @('HKLM:\Software\Classes\CLSID', 'HKCU:\Software\Classes\CLSID',
                      'HKLM:\Software\Wow6432Node\Classes\CLSID')) {
    $ip = "$root\$clsid\InprocServer32"
    if (Test-Path $ip) {
      $d = [string](Get-ItemProperty $ip).'(default)'
      if ($d) { return $d }
    }
  }
  return ''
}

$o.shellHooks = @(foreach ($k in @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects')) {
  if (Test-Path $k) {
    (Get-Item $k).Property | Where-Object { $_ -ne '(default)' } | ForEach-Object {
      $dll = Resolve-Clsid $_
      $r = Resolve-Dll $dll
      [pscustomobject]@{ key=$k; name=$_; dll=$dll
                         path=$(if($r){$r.path}else{''}); exists=$(if($r){$r.exists}else{$false}) } }
    Get-ChildItem $k | ForEach-Object {
      $dll = Resolve-Clsid $_.PSChildName
      $r = Resolve-Dll $dll
      [pscustomobject]@{ key=$k; name=$_.PSChildName; dll=$dll
                         path=$(if($r){$r.path}else{''}); exists=$(if($r){$r.exists}else{$false}) } } } })

# --- screensaver + accessibility backdoor --------------------------------
$o.screensaver = Get-Val 'HKCU:\Control Panel\Desktop' 'SCRNSAVE.EXE'
$o.accessibility = @(foreach ($n in @('sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','atbroker.exe')) {
  $p = "C:\Windows\System32\$n"
  if (Test-Path $p) {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    [pscustomobject]@{ name=$n; status=[string]$s.Status
                       signer=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''} } } })

# --- execution history (UserAssist) --------------------------------------
function Rot13([string]$s) {
  -join ($s.ToCharArray() | ForEach-Object {
    if ($_ -match '[a-zA-Z]') {
      $b = if ([char]::IsUpper($_)) { 65 } else { 97 }
      [char]((([int][char]$_ - $b + 13) % 26) + $b)
    } else { $_ } })
}
$ua = New-Object System.Collections.ArrayList
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' |
  ForEach-Object {
    $c = Join-Path $_.PSPath 'Count'
    if (Test-Path $c) {
      $props = Get-ItemProperty $c
      $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        $d = $_.Value
        if ($d -is [byte[]] -and $d.Length -ge 68) {
          $runs = [BitConverter]::ToInt32($d, 4)
          $ft   = [BitConverter]::ToInt64($d, 60)
          if ($ft -gt 0 -and $runs -gt 0) {
            [void]$ua.Add([pscustomobject]@{
              name = Rot13 $_.Name
              runs = $runs
              last = [DateTime]::FromFileTime($ft).ToString('o') }) } } } } }
$o.userAssist = @($ua | Sort-Object last -Descending | Select-Object -First 40)

# --- running processes, for masquerade and parentage checks ---------------
$o.procs = @(Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{ pid=$_.ProcessId; ppid=$_.ParentProcessId
                     name=$_.Name; path=$_.ExecutablePath } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""

# Defaults. Anything else in these slots was put there deliberately.
STOCK = {
    "shell": re.compile(r"^explorer\.exe$", re.I),
    "userinit": re.compile(r"^C:\\Windows\\system32\\userinit\.exe,?$", re.I),
    "taskman": re.compile(r"^$"),
    "appsetup": re.compile(r"^$"),
}
STOCK_LSA = re.compile(r"^(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|"
                       r"negotiate|scecli|rassfm|kdcsvc|ntlm)$", re.I)
MS_SIGNER = re.compile(r"CN=Microsoft Windows|CN=Microsoft Corporation", re.I)
STOCK_TIME = re.compile(r"w32time\.dll|vmictimeprovider\.dll", re.I)

# A bare DLL name loads out of System32, which needs admin to write. An explicit
# path that is *not* under System32 is the interesting case.
OFF_SYSTEM32 = re.compile(r"[\\/]")

# Windows' own Active Setup entries; these run once per user by design.
STOCK_ACTIVE_SETUP = re.compile(r"mscories\.dll|ie4uinit|shell32\.dll|"
                                r"themeui\.dll|occache\.dll", re.I)


def audit():
    data = _ps_json(PS_ASEP, timeout=240)
    if data is None:
        return [_finding("asep", "medium", "ASEP audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- loader abuse ------------------------------------------------------
    for a in _aslist(data.get("appinit")):
        out.append(_finding("loader", "critical", "AppInit_DLLs is set",
                            f"{a.get('dlls')} (LoadAppInit_DLLs={a.get('enabled')}) — "
                            f"this DLL loads into nearly every process that uses "
                            f"user32", a.get("key", "")))

    for i in _aslist(data.get("ifeo")):
        target, dbg = i.get("target", ""), i.get("debugger", "")
        if dbg:
            out.append(_finding("loader", "critical",
                                "Image File Execution Options debugger",
                                f"launching {target} actually runs: {dbg[:90]}",
                                "IFEO"))
        elif str(i.get("globalFlag")) == "512":
            out.append(_finding("loader", "high", "silent process exit monitoring",
                                f"{target} has GlobalFlag 512 set", "IFEO"))

    # -- logon chain -------------------------------------------------------
    wl = data.get("winlogon") or {}
    for key, pat in STOCK.items():
        val = (wl.get(key) or "").strip()
        if val and not pat.match(val):
            out.append(_finding("logon", "critical", f"Winlogon {key} modified",
                                f"{val[:100]} — this runs at every logon",
                                "Winlogon"))

    for a in _aslist(data.get("activeSetup")):
        stub = a.get("stub") or ""
        if STOCK_ACTIVE_SETUP.search(stub):
            continue
        if re.search(r"\\appdata\\|\\temp\\|powershell|cmd\.exe|mshta|rundll32",
                     stub, re.I):
            out.append(_finding("logon", "high", "Active Setup stub runs a command",
                                f"{stub[:100]}", a.get("key", "")))

    # -- COM hijacking -----------------------------------------------------
    # Per-user CLSID registrations are how OneDrive, Teams and every other
    # per-user install legitimately work, so their mere existence means nothing.
    # What matters is a registration whose DLL is somewhere untrustworthy, is a
    # scripting host, or does not exist at all (a hijack waiting to be filled).
    benign_com = 0
    for c in _aslist(data.get("comHijack")):
        dll = c.get("dll") or ""
        path = c.get("path") or dll
        why = None
        if re.search(r"scrobj\.dll|mshta|\bscriptlet\b|^https?:", dll, re.I):
            why, sev = "registered to a scripting host", "critical"
        elif re.search(r"\\temp\\|\\downloads\\|\\users\\public\\|\\programdata\\",
                       path, re.I):
            why, sev = "DLL sits in a world-writable directory", "critical"
        elif c.get("exists") is False:
            why, sev = "target DLL does not exist — an empty slot anything could fill", "high"
        if why is None:
            benign_com += 1
            continue
        out.append(_finding("com", sev, "suspicious per-user COM registration",
                            f"{c.get('clsid')} → {path[:80]} ({why})",
                            "HKCU\\Software\\Classes\\CLSID"))
    if benign_com:
        out.append(_finding("com", "ok", "per-user COM registrations",
                            f"{benign_com} normal (per-user app installs)",
                            "HKCU\\Software\\Classes\\CLSID"))

    # -- privileged plumbing ----------------------------------------------
    lsa = data.get("lsa") or {}
    for kind in ("security", "notification", "authentication"):
        for pkg in re.split(r"[,\s]+", lsa.get(kind) or ""):
            pkg = pkg.strip().strip('"')
            if pkg and not STOCK_LSA.match(pkg):
                out.append(_finding("privileged", "critical",
                                    f"non-standard LSA {kind} package",
                                    f"{pkg} — loads inside LSASS",
                                    "Control\\Lsa"))

    # Printer vendors ship monitors and Windows ships several; a bare DLL name
    # loads from System32, which is not something a normal user can write to.
    # Only a monitor pointing at an explicit path outside System32 is notable.
    for m in _aslist(data.get("printMonitors")):
        dll = m.get("dll") or ""
        if not dll:
            continue
        if OFF_SYSTEM32.search(dll):
            out.append(_finding("privileged", "high", "print monitor loads from a path",
                                f"{m.get('name')} → {dll} (loads into spoolsv as SYSTEM)",
                                "Print\\Monitors"))

    for n in _aslist(data.get("netsh")):
        dll = n.get("dll") or ""
        if dll and OFF_SYSTEM32.search(dll):
            out.append(_finding("privileged", "high", "netsh helper loads from a path",
                                f"{n.get('name')} → {dll}", "Microsoft\\Netsh"))

    for t in _aslist(data.get("timeProviders")):
        dll = t.get("dll") or ""
        if dll and not STOCK_TIME.search(dll):
            out.append(_finding("privileged", "high", "non-standard time provider",
                                f"{t.get('name')} → {dll}", "W32Time\\TimeProviders"))

    for s in _aslist(data.get("shellHooks")):
        path = s.get("path") or s.get("dll") or ""
        if not path:
            continue
        if re.search(r"\\temp\\|\\downloads\\|\\users\\public\\|\\appdata\\", path, re.I):
            sev, why = "critical", "loads from a user-writable directory"
        elif s.get("exists") is False:
            sev, why = "high", "target DLL is missing"
        else:
            continue  # a shell extension pointing at a real DLL under Windows
        out.append(_finding("loader", sev, "Explorer extension loads untrusted code",
                            f"{s.get('name')} → {path[:80]} ({why})",
                            (s.get("key") or "").split("\\")[-1]))

    # -- screensaver + accessibility --------------------------------------
    ss = data.get("screensaver") or ""
    if ss and not re.search(r"\\windows\\system32\\\w+\.scr$", ss, re.I):
        out.append(_finding("logon", "high", "screensaver runs a non-standard program",
                            ss[:100], "Control Panel\\Desktop"))

    for a in _aslist(data.get("accessibility")):
        status, signer = a.get("status"), a.get("signer") or ""
        if status != "Valid" or not MS_SIGNER.search(signer):
            out.append(_finding(
                "logon", "critical", "accessibility binary is not genuine",
                f"{a.get('name')} — signature {status}, signer "
                f"{signer[:50] or 'none'}. These run as SYSTEM from the logon "
                f"screen before anyone signs in.", "System32"))

    # -- masquerading + parentage -----------------------------------------
    procs = _aslist(data.get("procs"))
    by_pid = {p.get("pid"): p for p in procs}
    for p in procs:
        name = (p.get("name") or "").lower()
        path = (p.get("path") or "").lower()
        expect = SYSTEM_BINARIES.get(name)
        if expect and path and not re.search(expect, path):
            out.append(_finding(
                "masquerade", "critical", "system binary running from the wrong place",
                f"{p.get('name')} [pid {p.get('pid')}] at {p.get('path')} — the real "
                f"one lives in System32", "Win32_Process"))

        parent = by_pid.get(p.get("ppid"))
        if not parent:
            continue
        pname = (parent.get("name") or "").lower()
        for ppat, cpat, why in BAD_PARENTAGE:
            if re.match(ppat, pname) and re.match(cpat, name):
                out.append(_finding(
                    "masquerade", "high", "unusual process parentage",
                    f"{parent.get('name')} → {p.get('name')} [pid {p.get('pid')}]: {why}",
                    p.get("path") or ""))
                break

    # -- execution history -------------------------------------------------
    for u in _aslist(data.get("userAssist"))[:25]:
        nm = u.get("name") or ""
        last = (u.get("last") or "").replace("T", " ")[:19]
        # UEME_* rows are UserAssist's own session counters, not programs, and
        # they carry nonsense timestamps.
        if nm.startswith("UEME_") or not last[:4].isdigit() or int(last[:4]) < 2000:
            continue
        out.append(_finding("history", "low", "program launched",
                            f"{nm.split(chr(92))[-1][:70]} — {u.get('runs')}×, "
                            f"last {last}", nm))

    return out


CAT_ORDER = {"loader": 0, "logon": 1, "com": 2, "privileged": 3,
             "masquerade": 4, "asep": 5, "history": 6}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (CAT_ORDER.get(x["category"], 9),
                                    SEV_ORDER.get(x["severity"], 9), x["title"]))
