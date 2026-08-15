"""Artifacts of how machines actually get compromised right now.

The other modules look for things that are *running* or *installed*. This one
looks for evidence of the initial access itself, because current intrusions are
increasingly things that happen once and leave no persistent process behind:

  ClickFix          A fake CAPTCHA page copies a command to the clipboard and
                    tells you to press Win+R and paste it. It is reportedly the
                    single largest initial-access technique in circulation, and
                    it leaves a perfect fingerprint: Windows records everything
                    typed into the Run dialog in the RunMRU registry key.

  Infostealers      Modern stealers run once, harvest browser cookies, session
                    tokens and saved passwords, and exit. Behavioural rules that
                    watch for persistence miss them entirely, because there is
                    no persistence. What they leave behind is access to the
                    browser credential stores and, often, a malicious extension.

  Session theft     Stolen cookies and OAuth tokens are replayed directly, so
                    the password and the second factor never come into it. A
                    browser extension with broad host permissions is one of the
                    cheapest ways to keep harvesting them.

It also reads Defender's own detection history, which is the cheapest possible
question to ask and the one most often skipped: has the antivirus already found
something and been ignored?
"""

import re

from .control import _aslist, _ps_json

# Command shapes that show up in ClickFix lures and in pasted-payload attacks.
PASTE_ATTACK = re.compile(
    r"powershell|pwsh|cmd(\.exe)?\s*/c|mshta|curl|wget|iwr|invoke-webrequest|"
    r"invoke-expression|\biex\b|bitsadmin|certutil|msiexec\s+/i\s+http|"
    r"regsvr32|rundll32|conhost|forfiles|\bftp\b|base64|frombase64string|"
    r"\.hta\b|\bwscript\b|\bcscript\b|http://|https://|\\\\[^\\]+\\",
    re.I,
)

# Browser credential and session stores. Anything but the browser reading these
# is worth knowing about.
CRED_STORES = re.compile(
    r"\\(Login Data|Cookies|Web Data|Local State|key4\.db|logins\.json|"
    r"cookies\.sqlite|places\.sqlite)$", re.I)

BROWSER_PROC = re.compile(r"^(chrome|msedge|firefox|opera|brave|vivaldi|"
                          r"chromium|thorium)\.exe$", re.I)

# Extension permissions that allow reading every page, including session tokens.
BROAD_PERMS = re.compile(r"<all_urls>|\*://\*/\*|http://\*/\*|https://\*/\*|"
                         r"webRequest|cookies|debugger|nativeMessaging|proxy",
                         re.I)


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


PS_INTRUSION = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. ClickFix: everything ever typed into the Win+R Run dialog ----------
$mru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
$o.runmru = @()
if (Test-Path $mru) {
  $p = Get-ItemProperty $mru
  $o.runmru = @($p.PSObject.Properties |
    Where-Object { $_.Name -match '^[a-z]$' } |
    ForEach-Object { [pscustomobject]@{ slot=$_.Name; cmd=[string]$_.Value } })
  $o.runmruOrder = [string]$p.MRUList
}

# --- 2. PowerShell console history (what was actually typed) --------------
$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
$o.psHistory = @()
if (Test-Path $hist) {
  $o.psHistoryPath = $hist
  # [string[]] is load-bearing: Get-Content attaches PSPath/PSDrive/PSProvider
  # note properties to every line it returns, and ConvertTo-Json -Depth serialises
  # that entire provider graph once per line. Left as-is this one field produced
  # ~700MB of JSON and took three minutes.
  $o.psHistory = [string[]]@(Get-Content $hist -Tail 300 |
                             Where-Object { $_.Trim() })
}

# --- 3. Defender's own detection history ----------------------------------
$o.threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending |
  Select-Object -First 40 | ForEach-Object {
    $t = $_
    [pscustomobject]@{
      time     = if ($t.InitialDetectionTime) { $t.InitialDetectionTime.ToString('o') } else { '' }
      action   = [string]$t.ActionSuccess
      status   = [string]$t.ThreatStatusID
      resources= [string]($t.Resources -join ' | ')
      id       = [string]$t.ThreatID
    } })
$o.threatNames = @(Get-MpThreat | Select-Object -First 40 |
  ForEach-Object { [pscustomobject]@{ name=[string]$_.ThreatName
                                      severity=[string]$_.SeverityID
                                      resources=[string]($_.Resources -join ' | ') } })

# --- 4. Browser extensions -------------------------------------------------
$ext = New-Object System.Collections.ArrayList
$chromiumRoots = @(
  @{n='Chrome'; p="$env:LOCALAPPDATA\Google\Chrome\User Data"},
  @{n='Edge';   p="$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
  @{n='Brave';  p="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"},
  @{n='Opera';  p="$env:APPDATA\Opera Software\Opera Stable"}
)
foreach ($b in $chromiumRoots) {
  if (-not (Test-Path $b.p)) { continue }
  Get-ChildItem "$($b.p)\*\Extensions\*\*\manifest.json" -ErrorAction SilentlyContinue |
    ForEach-Object {
      # -Encoding UTF8 matters: PowerShell 5.1 reads as ANSI by default and
      # mangles any non-ASCII character in an extension's name.
      $m = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
      [void]$ext.Add([pscustomobject]@{
        browser = $b.n
        id      = $_.Directory.Parent.Name
        name    = [string]$m.name
        version = [string]$m.version
        perms   = [string](@($m.permissions) + @($m.host_permissions) -join ',')
        updateUrl = [string]$m.update_url
        location  = 'profile'
        installed = $_.LastWriteTime.ToString('o')
      }) }
}
# Firefox keeps its inventory in one JSON file per profile. Its `location` field
# separates add-ons *you* installed ("app-profile") from the ones Mozilla ships
# with the browser ("app-builtin", "app-system-defaults") -- the built-ins have
# no update URL by design, so without this they all look sideloaded.
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions.json" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $j = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $j.addons | Where-Object { $_.type -eq 'extension' -and $_.active } | ForEach-Object {
      [void]$ext.Add([pscustomobject]@{
        browser='Firefox'; id=[string]$_.id
        name=[string]$_.defaultLocale.name; version=[string]$_.version
        perms=[string](@($_.userPermissions.permissions) + @($_.userPermissions.origins) -join ',')
        updateUrl=[string]$_.updateURL
        location=[string]$_.location
        signed=[string]$_.signedState
        installed=if($_.installDate){([DateTimeOffset]::FromUnixTimeMilliseconds($_.installDate)).ToString('o')}else{''}
      }) } }
$o.extensions = @($ext)

# --- 5. Recently written executables in staging directories ---------------
$cut = (Get-Date).AddDays(-14)
$o.recentExe = @(Get-ChildItem -File -ErrorAction SilentlyContinue -Path @(
    "$env:TEMP", "$env:USERPROFILE\Downloads", "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp", "$env:PUBLIC") -Recurse -Depth 2 -Include `
    *.exe,*.dll,*.scr,*.ps1,*.bat,*.cmd,*.vbs,*.hta,*.js,*.jar |
  Where-Object { $_.LastWriteTime -gt $cut -and
                 $_.FullName -notmatch '\\(Mozilla|Firefox|Google\\Chrome|Microsoft\\Edge)\\' -and
                 $_.Name -notmatch '^(prefs|user|handlers|search|extension-preferences)\.js$' } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 60 |
  ForEach-Object {
    $s = Get-AuthenticodeSignature -LiteralPath $_.FullName
    [pscustomobject]@{ path=$_.FullName; size=$_.Length
                       written=$_.LastWriteTime.ToString('o')
                       sig=[string]$s.Status } })

# --- 6. Who has the browser credential stores open ------------------------
$o.credAccess = @()
try {
  $stores = Get-ChildItem -File -ErrorAction SilentlyContinue -Path @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Login Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json") |
    ForEach-Object { [pscustomobject]@{ path=$_.FullName
                                        written=$_.LastWriteTime.ToString('o') } }
  $o.credAccess = @($stores)
} catch {}

$json = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""

SUSPICIOUS_HISTORY = re.compile(
    r"(iwr|invoke-webrequest|curl|wget)[^|;\n]*\|\s*(iex|invoke-expression)|"
    r"frombase64string|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{30,}|"
    r"downloadstring|downloadfile|"
    r"set-mppreference\s+-disable|add-mppreference\s+-exclusionpath|"
    r"disable-windowsoptionalfeature|"
    r"new-object\s+system\.net\.webclient|"
    r"bypass\s+-\w*\s*(file|command)|start-process\s+-verb\s+runas",
    re.I,
)

# Extensions that ship with the browser or are installed by Windows itself.
STOCK_EXT = re.compile(r"^(Chrome Web Store Payments|Google Docs Offline|"
                       r"Microsoft Defender Browser Protection|"
                       r"Edge relevant text changes|Web Store|"
                       r"Chrome PDF Viewer|Firefox Screenshots)$", re.I)


def audit():
    data = _ps_json(PS_INTRUSION, timeout=300)
    if data is None:
        return [_finding("clickfix", "medium", "intrusion audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- 1. ClickFix ------------------------------------------------------
    runmru = _aslist(data.get("runmru"))
    for r in runmru:
        cmd = (r.get("cmd") or "").rstrip("\\1")
        if not cmd:
            continue
        if PASTE_ATTACK.search(cmd):
            out.append(_finding(
                "clickfix", "critical",
                "a command was typed or pasted into the Win+R Run dialog",
                cmd[:150],
                "RunMRU — this is the artefact ClickFix leaves. If you did not "
                "type this yourself, treat the machine as compromised."))
        else:
            out.append(_finding("clickfix", "low", "Run dialog history",
                                cmd[:100], "RunMRU"))
    if not runmru:
        out.append(_finding("clickfix", "ok", "Run dialog history is empty",
                            "nothing has been typed into Win+R", "RunMRU"))

    # -- 2. PowerShell history --------------------------------------------
    hist = _aslist(data.get("psHistory"))
    hits = [h for h in hist if isinstance(h, str) and SUSPICIOUS_HISTORY.search(h)]
    for h in hits[:15]:
        out.append(_finding("clickfix", "high", "suspicious PowerShell command in history",
                            h[:150], data.get("psHistoryPath", "")))
    if hist and not hits:
        out.append(_finding("clickfix", "ok", "PowerShell history clean",
                            f"{len(hist)} recent commands, none matching known "
                            f"download-and-execute or defence-tampering shapes", ""))

    # -- 3. Defender's own findings ---------------------------------------
    for t in _aslist(data.get("threatNames")):
        out.append(_finding("av", "critical", "Defender detected a threat",
                            f"{t.get('name')} — {(t.get('resources') or '')[:110]}",
                            "Get-MpThreat"))
    # Defender logs one detection per scan, so the same file appears repeatedly.
    # Collapse by resource and keep the worst outcome and latest time.
    detections = {}
    for d in _aslist(data.get("threats")):
        key = (d.get("resources") or "")[:200]
        clean = str(d.get("action")).lower() == "true"
        e = detections.setdefault(key, {"n": 0, "clean": True, "last": ""})
        e["n"] += 1
        e["clean"] = e["clean"] and clean
        e["last"] = max(e["last"], d.get("time") or "")
    for res, e in sorted(detections.items(), key=lambda kv: kv[1]["last"],
                         reverse=True)[:10]:
        out.append(_finding(
            "av", "low" if e["clean"] else "critical",
            "Defender detection" + ("" if e["clean"] else " NOT remediated"),
            f"{res[:110]}" + (f"  (×{e['n']})" if e["n"] > 1 else ""),
            e["last"].replace("T", " ")[:19]))

    # -- 4. browser extensions --------------------------------------------
    exts = _aslist(data.get("extensions"))
    for e in exts:
        name = e.get("name") or e.get("id") or "?"
        if name.startswith("__MSG_") or STOCK_EXT.match(name):
            continue
        # Browser-shipped add-ons are not "sideloaded" in any meaningful sense.
        location = (e.get("location") or "").lower()
        if location.startswith("app-") and location != "app-profile":
            continue
        # Mozilla ships several add-ons under its own IDs; they carry no update
        # URL because the browser updates them.
        if re.search(r"@mozilla\.(org|com)$", e.get("id") or "", re.I):
            continue
        perms = e.get("perms") or ""
        sideloaded = not (e.get("updateUrl") or "")
        broad = BROAD_PERMS.search(perms)
        if broad and sideloaded:
            sev, why = "critical", "broad permissions and no update URL (sideloaded)"
        elif sideloaded:
            sev, why = "high", "no update URL — installed outside the store"
        elif broad:
            sev, why = "low", "can read every page you visit"
        else:
            continue
        out.append(_finding("extension", sev, f"{e.get('browser')} extension",
                            f"{name} v{e.get('version')} — {why}",
                            f"{e.get('id')}  perms: {perms[:90]}"))
    out.append(_finding("extension", "ok", "browser extensions",
                        f"{len(exts)} installed across all browsers", ""))

    # -- 5. staged executables --------------------------------------------
    for f in _aslist(data.get("recentExe"))[:25]:
        path, sig = f.get("path") or "", f.get("sig") or ""
        in_temp = re.search(r"\\temp\\|\\public\\", path, re.I)
        if sig in ("NotSigned", "HashMismatch", "NotTrusted") and in_temp:
            sev = "high"
        elif sig in ("NotSigned", "HashMismatch", "NotTrusted"):
            sev = "low"
        else:
            continue
        out.append(_finding(
            "staging", sev, "recently written unsigned executable",
            f"{path.split(chr(92))[-1]} — {sig}, "
            f"{(f.get('written') or '').replace('T', ' ')[:19]}", path))

    return out


CAT_ORDER = {"av": 0, "clickfix": 1, "extension": 2, "staging": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (CAT_ORDER.get(x["category"], 9),
                                    SEV_ORDER.get(x["severity"], 9), x["title"]))
