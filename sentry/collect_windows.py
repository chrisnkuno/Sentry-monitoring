"""Collect Windows processes and TCP connections through WSL interop.

Everything happens in one powershell.exe invocation because crossing the interop
boundary costs ~1s; doing it per-process would make scanning unusable. The
payload comes back base64-encoded so console codepage quirks can't corrupt it.
"""

import base64
import json
import os
import re
import shutil
import stat
import subprocess

from .util import fingerprint

HOST = "win"

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'

$procs = Get-CimInstance Win32_Process | ForEach-Object {
    [pscustomobject]@{
        pid  = $_.ProcessId
        ppid = $_.ParentProcessId
        name = $_.Name
        exe  = $_.ExecutablePath
        cmd  = $_.CommandLine
    }
}

$conns = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conns = Get-NetTCPConnection | Where-Object { $_.State -ne 'Bound' } | ForEach-Object {
        [pscustomobject]@{
            pid    = $_.OwningProcess
            proto  = 'tcp'
            lip    = $_.LocalAddress
            lport  = $_.LocalPort
            rip    = $_.RemoteAddress
            rport  = $_.RemotePort
            state  = [string]$_.State
        }
    }
}

$payload = [pscustomobject]@{ procs = @($procs); conns = @($conns) } | ConvertTo-Json -Depth 4 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
"""

# Hosts that run someone else's code; the argument is the real identity.
SCRIPT_HOSTS = re.compile(
    r"^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|python[\d.]*|node|"
    r"ruby|perl|php|java|javaw|wsl|bash)\.exe$",
    re.I,
)
SCRIPT_EXT = re.compile(r"\.(ps1|psm1|bat|cmd|vbs|js|jse|wsf|py|rb|pl|php|jar|hta)\b", re.I)

_PS = None


def ensure_interop() -> bool:
    """Make sure WSL_INTEROP points at a live socket.

    Launching a Windows binary from WSL goes through a per-session Unix socket
    named in $WSL_INTEROP. A systemd *user service* inherits no such variable —
    and a value inherited from a login shell goes stale the moment that session
    ends. Either way the daemon silently loses every Windows collector while
    looking perfectly healthy, so we resolve a working socket ourselves instead
    of trusting the environment.
    """
    current = os.environ.get("WSL_INTEROP")
    if current and os.path.exists(current):
        return True

    try:
        candidates = [
            os.path.join("/run/WSL", n)
            for n in os.listdir("/run/WSL")
            if n.endswith("_interop")
        ]
    except OSError:
        return False

    # Newest socket first: it belongs to the most recent session, which is the
    # one most likely to still be attached to a running Windows side.
    for path in sorted(candidates, key=lambda p: os.stat(p).st_mtime, reverse=True):
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode):
                os.environ["WSL_INTEROP"] = path
                return True
        except OSError:
            continue
    return False


# Where powershell.exe lives when PATH cannot help. A login shell gets the
# Windows directories appended to PATH by WSL; a systemd service does not, so
# shutil.which() finds nothing there and every Windows collector goes quiet.
FALLBACK_PS = [
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/Program Files/PowerShell/7/pwsh.exe",
]


def find_powershell() -> str:
    found = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if found:
        return found
    for path in FALLBACK_PS:
        if os.path.exists(path):
            return path
    return ""


def available() -> bool:
    """True when the Windows side is reachable from here."""
    global _PS
    if not _PS:
        _PS = find_powershell()
    return bool(_PS) and ensure_interop()


def _split_args(cmd: str):
    """Tokenize a Windows command line, honoring double quotes."""
    return [t.strip('"') for t in re.findall(r'"[^"]*"|\S+', cmd or "")]


def _script_target(cmd: str, exe_base: str) -> str:
    if not SCRIPT_HOSTS.match(exe_base):
        return ""
    for arg in _split_args(cmd)[1:]:
        if arg.startswith(("-", "/")):
            continue
        if SCRIPT_EXT.search(arg):
            return arg
    return ""


def collect(timeout: int = 45):
    """Return a list of process records for the Windows side (empty if unreachable)."""
    if not available():
        return []
    try:
        res = subprocess.run(
            [_PS, "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
            capture_output=True,
            timeout=timeout,
            cwd="/",  # avoids the UNC-path warning when cwd is a Linux dir
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    blob = res.stdout.decode("ascii", "ignore").strip().replace("\r", "").replace("\n", "")
    if not blob:
        return []
    try:
        data = json.loads(base64.b64decode(blob).decode("utf-8", "replace"))
    except Exception:
        return []

    by_pid = {}
    for c in data.get("conns") or []:
        # Windows reports pid 0 for connections it declines to attribute; that
        # is not the System Idle Process actually talking to the internet.
        pid = c.get("pid")
        by_pid.setdefault(0 if pid in (0, None) else pid, []).append({
            "proto": c.get("proto", "tcp"),
            "local_ip": c.get("lip", ""),
            "local_port": c.get("lport", 0),
            "remote_ip": c.get("rip", ""),
            "remote_port": c.get("rport", 0),
            "state": c.get("state", ""),
        })

    procs = []
    for p in data.get("procs") or []:
        pid = p.get("pid")
        exe = p.get("exe") or ""
        name = p.get("name") or ""
        cmd = p.get("cmd") or name
        if pid == 0:
            name = "(unattributed)"
        exe_base = os.path.basename(exe.replace("\\", "/")) or name
        script = _script_target(cmd, exe_base)
        ident_exe = script if script else exe

        procs.append({
            "host": HOST,
            "pid": pid,
            "ppid": p.get("ppid", 0),
            "name": name,
            "exe": exe,
            "script": script,
            "cmdline": cmd,
            "user": "",  # per-process owner lookup is too slow to do on every scan
            "conns": by_pid.get(pid, []),
            "fp": fingerprint(HOST, ident_exe or name, cmd, ""),
        })

    return procs
