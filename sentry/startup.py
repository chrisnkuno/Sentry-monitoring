"""Explain what ran at boot — specifically, windows that flash open and close.

A console window that appears for a fraction of a second and vanishes is a
process with a console attached that exited immediately: `cmd.exe /c ...`,
`wscript`, `cscript`, a `.bat` file, or PowerShell without `-WindowStyle Hidden`.
Interval sampling will never catch one reliably, so this module does not try.
It reconstructs the event after the fact from three records that persist:

  1. Task Scheduler's operational log, event 129, which names the task and the
     process it launched, with a timestamp
  2. the autostart inventory, filtered to entries that would *show a window* —
     these are the candidates, whether or not they ran this boot
  3. the Windows Error Reporting and Application logs, which catch the ones
     that flashed because they crashed

Cross-referencing 1 against 2 usually names the culprit outright.
"""

import re

from .control import _aslist, _ps_json

# Things that get a console window unless explicitly hidden.
CONSOLE_HOST = re.compile(
    r"\bcmd(\.exe)?\b|\bpowershell(\.exe)?\b|\bpwsh(\.exe)?\b|\bwscript(\.exe)?\b|"
    r"\bcscript(\.exe)?\b|\bmshta(\.exe)?\b|\bconhost(\.exe)?\b|"
    r"\.bat\b|\.cmd\b|\.vbs\b|\.js\b|\.ps1\b|\bcurl(\.exe)?\b|\brobocopy\b|\bschtasks\b",
    re.I,
)
HIDDEN_FLAG = re.compile(r"-w(indowstyle)?\s+hidden|/b\b|CreateNoWindow", re.I)


def _finding(category, severity, title, detail, where=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


PS_BOOT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$o.bootTime = $boot.ToString('o')

# --- what Task Scheduler launched since boot (129 = created task process) ---
$o.taskRuns = @(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=129,100,200;
        StartTime=$boot } -MaxEvents 200 |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      time = $_.TimeCreated.ToString('o')
      id   = $_.Id
      task = [string]$d['TaskName']
      path = [string]$d['Path']
      cmd  = [string]$d['ActionName']
    } })

# --- every autostart entry, with enough detail to tell if it shows a window ---
$items = New-Object System.Collections.ArrayList
foreach ($k in @(
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
  $p = Get-ItemProperty -Path $k
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
    ForEach-Object { [void]$items.Add([pscustomobject]@{
      kind='run-key'; name=$_.Name; cmd=[string]$_.Value; where=$k }) } }
}
Get-ChildItem -File -Path @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") |
  ForEach-Object { [void]$items.Add([pscustomobject]@{
    kind='startup-folder'; name=$_.Name; cmd=$_.FullName; where=$_.DirectoryName }) }
Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and
    ($_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Boot|Logon' }) } |
  ForEach-Object {
    $t = $_
    $a = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
    [void]$items.Add([pscustomobject]@{
      kind='boot-task'; name=$t.TaskName; cmd=$a; where=$t.TaskPath }) }
$o.autostart = @($items)

# --- things that crashed or errored around boot, another cause of a flash ---
$o.crashes = @(Get-WinEvent -FilterHashtable @{
        LogName='Application'; Level=1,2; StartTime=$boot } -MaxEvents 60 |
  ForEach-Object { [pscustomobject]@{
      time=$_.TimeCreated.ToString('o'); src=[string]$_.ProviderName
      msg=(($_.Message -replace "`r`n",' ') -replace '\s+',' ') } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def audit():
    data = _ps_json(PS_BOOT, timeout=240)
    if data is None:
        return [_finding("boot", "medium", "startup analysis unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []
    boot = data.get("bootTime") or "?"
    out.append(_finding("boot", "ok", "last boot", boot.replace("T", " ")[:19], ""))

    # -- autostart entries that would visibly flash ------------------------
    flashers = []
    for it in _aslist(data.get("autostart")):
        cmd = it.get("cmd") or ""
        if CONSOLE_HOST.search(cmd) and not HIDDEN_FLAG.search(cmd):
            flashers.append(it)

    for it in flashers:
        cmd = it.get("cmd") or ""
        # A script host launching from a user-writable path at every boot is the
        # shape worth acting on; vendor updaters are the boring explanation.
        sev = "high" if re.search(r"\\appdata\\|\\temp\\|\\users\\public\\|"
                                  r"\\downloads\\|\\programdata\\", cmd, re.I) else "medium"
        out.append(_finding(
            "flash", sev, f"autostart shows a console window ({it.get('kind')})",
            f"{it.get('name')} → {cmd[:110]}", it.get("where") or ""))

    if not flashers:
        out.append(_finding("flash", "ok", "no window-showing autostart entries",
                            "nothing in Run keys, the startup folder or boot-triggered "
                            "tasks launches a visible console host", ""))

    # -- what actually ran this boot ---------------------------------------
    runs = [r for r in _aslist(data.get("taskRuns")) if r.get("task")]
    seen = {}
    for r in runs:
        seen.setdefault(r.get("task"), r)
    for task, r in list(seen.items())[:40]:
        blob = f"{task} {r.get('cmd') or ''} {r.get('path') or ''}"
        ms = task.startswith("\\Microsoft\\")
        sev = "low" if ms else "medium"
        if CONSOLE_HOST.search(blob) and not ms:
            sev = "high"
        out.append(_finding("ran", sev, "task ran at boot",
                            f"{task}" + (f" → {r.get('path')}" if r.get("path") else ""),
                            (r.get("time") or "").replace("T", " ")[:19]))

    if not runs:
        out.append(_finding("ran", "medium", "task history unavailable",
                            "the Task Scheduler operational log is empty or not "
                            "readable — enable it in Task Scheduler → View → "
                            "Show All Tasks History to capture the next boot",
                            "Microsoft-Windows-TaskScheduler/Operational"))

    for c in _aslist(data.get("crashes"))[:15]:
        out.append(_finding("ran", "low", "error logged since boot",
                            f"{c.get('src')}: {(c.get('msg') or '')[:100]}",
                            (c.get("time") or "").replace("T", " ")[:19]))

    return out


CAT_ORDER = {"flash": 0, "ran": 1, "boot": 2}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (CAT_ORDER.get(x["category"], 9),
                                    SEV_ORDER.get(x["severity"], 9), x["title"]))
