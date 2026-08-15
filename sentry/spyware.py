"""Look for commodity spyware, stalkerware and unwanted monitoring.

The sophisticated end of this problem needs a kernel driver. The unsophisticated
end — which is most of it — leaves obvious traces, and those are what this
module reads:

  * Windows records which application used the microphone, camera or location
    and exactly when, in the CapabilityAccessManager consent store. Nothing that
    records you through the normal APIs escapes this ledger.
  * Monitoring tools have to survive reboot, so they appear in autostart. Almost
    none of them are signed by a recognizable vendor. Checking the Authenticode
    signature of every autostart binary is a very high-signal, cheap test.
  * Anything that can change your volume or type for you is either an HID device
    sending consumer-control codes, or software with an input hook. Both are
    enumerable.
"""

import re

from .control import _ps_json, _aslist

# Names used by consumer monitoring, parental-control and stalkerware products.
# Matching one is a prompt to look, not a verdict.
STALKERWARE = re.compile(
    r"actualspy|ardamax|blurspy|cocospy|couplevow|cerberus|clevguard|"
    r"eyezy|flexispy|flexible?spy|hoverwatch|ikeymonitor|iwantspy|"
    r"kidsguard|kidlogger|mobistealth|mspy|minspy|neatspy|netbull|"
    r"pcpandora|perfectkeylogger|refog|realtime-?spy|revealer|spyagent|"
    r"spyera|spyhuman|spyic|spyier|spytech|spyzie|snoopza|"
    r"teensafe|thetruthspy|umobix|webwatcher|wolfeye|xnspy|"
    r"keylog|keystroke|screenshot.?monitor|employee.?monitor|"
    r"activtrak|hubstaff|teramind|veriato|interguard|workpuls|"
    r"desktime|timedoctor|controlio",
    re.I,
)

# Vendor software that legitimately drives volume and media keys. Present so the
# audit can say "this is probably your keyboard" instead of leaving you guessing.
INPUT_VENDORS = re.compile(
    r"logi|logitech|lghub|icue|corsair|razer|synapse|steelseries|"
    r"nahimic|sonic ?studio|realtek|dolby|armoury|asus|msi|alienware|"
    r"gamebar|xbox|elgato|streamdeck|touchportal|autohotkey|powertoys",
    re.I,
)

CAPABILITIES = ("microphone", "webcam", "location")


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


PS_SPY = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. Who used the microphone / camera / location, and when -------------
$caps = New-Object System.Collections.ArrayList
foreach ($hive in @('HKCU:','HKLM:')) {
  $base = "$hive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
  foreach ($cap in @('microphone','webcam','location')) {
    $capPath = Join-Path $base $cap
    if (-not (Test-Path $capPath)) { continue }
    foreach ($k in (Get-ChildItem $capPath)) {
      # Desktop (non-Store) apps are nested one level deeper under NonPackaged,
      # with their path encoded using '#' in place of the separators.
      $leaves = if ($k.PSChildName -eq 'NonPackaged') { Get-ChildItem $k.PSPath } else { @($k) }
      foreach ($l in $leaves) {
        $v = Get-ItemProperty $l.PSPath
        if ($null -eq $v.LastUsedTimeStart) { continue }
        $st = [int64]$v.LastUsedTimeStart
        $sp = [int64]$v.LastUsedTimeStop
        [void]$caps.Add([pscustomobject]@{
          cap   = $cap
          hive  = $hive
          app   = ($l.PSChildName -replace '#','\')
          start = if ($st -gt 0) { [DateTime]::FromFileTime($st).ToString('o') } else { '' }
          stop  = if ($sp -gt 0) { [DateTime]::FromFileTime($sp).ToString('o') } else { '' }
          inUse = ($st -gt 0 -and $sp -eq 0)
        })
      }
    }
  }
}
$o.caps = @($caps)

# --- 2. Every autostart binary, with its Authenticode signature -----------
$paths = New-Object System.Collections.ArrayList
$shell = New-Object -ComObject WScript.Shell
function Add-Path([string]$cmd) {
  if (-not $cmd) { return }
  $c = $cmd.Trim()
  # Pull the executable out of a command line, quoted or not.
  if ($c.StartsWith('"')) { $p = ($c -split '"')[1] }
  else { $m = [regex]::Match($c, '^(.*?\.(exe|dll|scr|com|bat|cmd|vbs|ps1|lnk))\b',
                             'IgnoreCase'); $p = if ($m.Success) { $m.Groups[1].Value } else { $c } }
  if (-not $p) { return }
  # A shortcut carries no signature of its own; follow it to the real binary.
  if ($p -like '*.lnk' -and (Test-Path -LiteralPath $p)) {
    $t = $shell.CreateShortcut($p).TargetPath
    if ($t) { $p = $t }
  }
  if (Test-Path -LiteralPath $p -PathType Leaf) { [void]$paths.Add($p) }
}

foreach ($k in @(
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
  $p = Get-ItemProperty -Path $k
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { Add-Path ([string]$_.Value) } }
}
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } |
  ForEach-Object { Add-Path $_.PathName }
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } |
  ForEach-Object { $_.Actions | ForEach-Object { Add-Path $_.Execute } }
Get-ChildItem -File -Path @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") |
  ForEach-Object { Add-Path $_.FullName }

$o.sigs = @($paths | Select-Object -Unique | ForEach-Object {
  $s = Get-AuthenticodeSignature -LiteralPath $_
  $f = Get-Item -LiteralPath $_
  [pscustomobject]@{
    path    = $_
    status  = [string]$s.Status
    signer  = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }
    written = $f.LastWriteTime.ToString('o')
  }
})

# --- 3. Input devices able to send volume/media commands ------------------
$o.hid = @(Get-CimInstance Win32_PnPEntity |
  Where-Object { $_.Name -match 'Consumer Control|HID Keyboard|Multimedia|Audio Control' -and
                 $_.Status -eq 'OK' } |
  Select-Object -First 25 @{n='name';e={$_.Name}}, @{n='id';e={$_.DeviceID}},
                          @{n='mfr';e={$_.Manufacturer}})

$o.audio = @(Get-CimInstance Win32_SoundDevice |
  Select-Object @{n='name';e={$_.Name}}, @{n='status';e={$_.Status}})

# --- 4. Software with a global input hook or accessibility control --------
# UIAccess / accessibility apps can drive the desktop; so can anything holding
# a low-level keyboard hook. Enumerating the modules is native work, so we look
# at the practical proxy: running processes from known input-automation tools.
$o.procs = @(Get-Process | ForEach-Object {
  [pscustomobject]@{ pid=$_.Id; name=$_.ProcessName; path=$_.Path;
                     title=$_.MainWindowTitle } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""

BAD_SIG = {"NotSigned", "HashMismatch", "NotTrusted", "UnknownError"}
TRUSTED_SIGNERS = re.compile(
    r"Microsoft (Corporation|Windows)|CN=Microsoft|Google LLC|Mozilla Corporation|"
    r"Intel Corporation|NVIDIA|Advanced Micro Devices|Realtek|Logitech|"
    r"Valve Corp|Riot Games|Proton AG|Dropbox|Adobe|Apple Inc|Cisco|"
    r"Discord|Spotify|Oracle|Citrix|VMware|Lenovo|Dell|HP Inc|ASUSTeK",
    re.I,
)


def audit(now_iso=None):
    data = _ps_json(PS_SPY, timeout=180)
    if data is None:
        return [_finding("access", "medium", "spyware audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. capability ledger ---------------------------------------------
    # Most recent first: "what touched the mic last" is the question being asked.
    caps = sorted(_aslist(data.get("caps")),
                  key=lambda c: c.get("start") or "", reverse=True)
    for c in caps:
        app = c.get("app") or "?"
        cap = c.get("cap")
        pretty = app.split("\\")[-1] if "\\" in app else app
        when = (c.get("start") or "").replace("T", " ")[:19]
        if c.get("inUse"):
            out.append(_finding(
                "access", "high", f"{cap} IN USE right now",
                f"{pretty} — since {when}", app))
        else:
            sev = "medium" if STALKERWARE.search(app) else "low"
            out.append(_finding(
                "access", sev, f"{cap} used", f"{pretty} — last used {when}",
                f"{app}  until {(c.get('stop') or '').replace('T', ' ')[:19]}"))
    if not caps:
        out.append(_finding("access", "low", "no capability history",
                            "no app has recorded microphone, camera or location use "
                            "(or the consent store is not readable from here)",
                            "CapabilityAccessManager"))

    # -- 2. autostart signatures ------------------------------------------
    for s in _aslist(data.get("sigs")):
        path, status = s.get("path", ""), s.get("status", "")
        signer = s.get("signer") or ""
        name = path.split("\\")[-1]
        if STALKERWARE.search(path):
            out.append(_finding("spyware", "critical",
                                "autostart matches known monitoring software",
                                name, path))
            continue
        if status in BAD_SIG:
            # Unsigned in Program Files is sloppy vendor practice; unsigned in a
            # directory you can write to without prompting is the shape that
            # matters, because anything on the machine could have put it there.
            in_user_space = re.search(
                r"\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\", path, re.I)
            out.append(_finding(
                "signing", "critical" if in_user_space else "medium",
                f"autostart binary is unsigned ({status})",
                f"{name} — no verified publisher"
                + (", running from a user-writable directory" if in_user_space else ""),
                path))
        elif status == "Valid" and signer and not TRUSTED_SIGNERS.search(signer):
            cn = re.search(r"CN=([^,]+)", signer)
            out.append(_finding("signing", "low",
                                "autostart signed by an unfamiliar publisher",
                                f"{name} — {cn.group(1) if cn else signer[:60]}", path))

    # -- 3. input / audio control -----------------------------------------
    # Windows creates one consumer-control node per HID collection, so a single
    # keyboard or headset shows up several times. Collapse them, and report the
    # count -- a device with a stuck or oversensitive volume control is by far
    # the most common cause of volume changing on its own.
    hid = _aslist(data.get("hid"))
    grouped = {}
    for h in hid:
        key = (h.get("name") or "", h.get("mfr") or "")
        grouped.setdefault(key, []).append(h.get("id", ""))
    for (nm, mfr), ids in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        n = len(ids)
        out.append(_finding(
            "input", "low", "device can send volume/media commands",
            f"{nm}" + (f"  [{mfr}]" if mfr else "")
            + (f"  ×{n} endpoints" if n > 1 else ""),
            "; ".join(ids[:4])))
    if hid:
        out.append(_finding(
            "input", "low", "volume changing on its own",
            f"{len(grouped)} distinct device(s) here can send volume commands — "
            f"unplug them one at a time to rule out a stuck media key before "
            f"suspecting software", "physical-first triage"))

    procs = _aslist(data.get("procs"))
    for p in procs:
        blob = f"{p.get('name')} {p.get('path') or ''}"
        if STALKERWARE.search(blob):
            out.append(_finding("spyware", "critical", "monitoring software running",
                                f"{p.get('name')} [pid {p.get('pid')}]",
                                p.get("path") or ""))
        elif INPUT_VENDORS.search(blob):
            out.append(_finding("input", "low", "input/media control software running",
                                f"{p.get('name')} [pid {p.get('pid')}]",
                                p.get("path") or ""))

    for a in _aslist(data.get("audio")):
        if a.get("status") not in ("OK", None):
            out.append(_finding("input", "medium", "audio device not healthy",
                                f"{a.get('name')} — {a.get('status')}", ""))

    return out


CAT_ORDER = {"spyware": 0, "access": 1, "input": 2, "signing": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (CAT_ORDER.get(f["category"], 9),
                                           SEV_ORDER.get(f["severity"], 9),
                                           f["title"]))
