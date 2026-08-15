"""Find processes that are hiding.

Every process list you can ask for comes from *some* API, and anything with
enough privilege can lie to that API. So no single enumeration is trusted here.
Instead we collect several views that reach the kernel by different routes and
diff them against each other. A process that appears in one view and not another
is either a race (it started or exited mid-scan) or something actively hiding —
and re-verification tells those two apart.

Linux views:
  readdir   -- os.listdir("/proc"), which goes through libc; an LD_PRELOAD
               rootkit hooks this one
  getdents  -- the raw getdents64 syscall via ctypes, bypassing libc entirely
  stat      -- directly stat()ing /proc/<pid> for each pid in a range, which
               works even when the directory entry is filtered out of listings
  sockets   -- socket inodes in /proc/net/* that no visible process claims

Windows views:
  wmi       -- Win32_Process (the CIM/WMI provider)
  api       -- Get-Process (toolhelp/NtQuerySystemInformation)
  tasklist  -- tasklist.exe (a third code path again)
  netstat   -- pids owning TCP connections
Userland hooks routinely patch one of these and miss the others.
"""

import ctypes
import ctypes.util
import errno
import os
import re
import struct
import subprocess
import time

from . import collect_windows
from .control import _ps_json

PROC = "/proc"

# stat() sweep bound. Linux allows pids up to 4194304, but sweeping that many is
# slow and pointless -- hidden processes launched at boot or by a service land
# in the low range. --deep raises this to the real pid_max.
DEFAULT_SWEEP = 65536


def _finding(severity, title, detail, evidence=""):
    return {"severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "host": ""}


# ---------------------------------------------------------------------------
# Linux view 1: libc readdir
# ---------------------------------------------------------------------------

def view_readdir():
    try:
        return {int(e) for e in os.listdir(PROC) if e.isdigit()}
    except OSError:
        return set()


# ---------------------------------------------------------------------------
# Linux view 2: raw getdents64 syscall, bypassing libc
# ---------------------------------------------------------------------------

SYS_getdents64 = {"x86_64": 217, "aarch64": 61, "armv7l": 217, "i686": 220}


def view_getdents():
    """List /proc through the syscall directly, so an LD_PRELOAD hook on
    readdir cannot filter the result."""
    nr = SYS_getdents64.get(os.uname().machine)
    if nr is None:
        return None  # unknown ABI; caller treats None as "view unavailable"
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except OSError:
        return None

    fd = os.open(PROC, os.O_RDONLY | os.O_DIRECTORY)
    pids = set()
    buf = ctypes.create_string_buffer(65536)
    try:
        while True:
            n = libc.syscall(nr, ctypes.c_int(fd), buf, ctypes.c_uint(len(buf)))
            if n <= 0:
                break
            off = 0
            raw = buf.raw
            while off < n:
                # struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen;
                #                         u8 d_type; char d_name[]; }
                reclen = struct.unpack_from("H", raw, off + 16)[0]
                if reclen == 0:
                    break
                name = raw[off + 19 : off + reclen].split(b"\x00", 1)[0]
                if name.isdigit():
                    pids.add(int(name))
                off += reclen
    except OSError:
        return None
    finally:
        os.close(fd)
    return pids


# ---------------------------------------------------------------------------
# Linux view 3: direct stat() sweep
# ---------------------------------------------------------------------------

def view_stat_sweep(limit=DEFAULT_SWEEP):
    """A pid whose directory entry is filtered from listings usually still
    resolves when you stat the path directly."""
    found = set()
    for pid in range(1, limit + 1):
        try:
            os.stat(f"{PROC}/{pid}")
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ESRCH, errno.EACCES, errno.EPERM):
                continue
            continue
        found.add(pid)
    return found


def pid_max():
    try:
        with open(f"{PROC}/sys/kernel/pid_max") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return DEFAULT_SWEEP


def _describe(pid):
    """Whatever we can learn about a pid the listings did not want to show."""
    info = {"pid": pid, "name": "?", "exe": "", "cmdline": "", "ppid": 0,
            "uid": "?", "tgid": pid}
    try:
        with open(f"{PROC}/{pid}/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("Name:"):
                    info["name"] = line.split("\t", 1)[-1].strip()
                elif line.startswith("PPid:"):
                    info["ppid"] = int(line.split()[1])
                elif line.startswith("Uid:"):
                    info["uid"] = line.split()[1]
                elif line.startswith("Tgid:"):
                    info["tgid"] = int(line.split()[1])
    except OSError:
        pass
    try:
        info["exe"] = os.readlink(f"{PROC}/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"{PROC}/{pid}/cmdline", "rb") as fh:
            info["cmdline"] = " ".join(
                a.decode("utf-8", "replace") for a in fh.read().split(b"\x00") if a
            )
    except OSError:
        pass
    return info


def _alive(pid):
    try:
        os.stat(f"{PROC}/{pid}")
        return True
    except OSError:
        return False


def is_thread(pid):
    """/proc/<tid> stats successfully for every thread, but readdir only lists
    thread-group leaders. A thread showing up in the stat sweep and not in the
    listing is how Linux is supposed to work, not something hiding."""
    try:
        with open(f"{PROC}/{pid}/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("Tgid:"):
                    return int(line.split()[1]) != pid
    except OSError:
        pass
    return False


# ---------------------------------------------------------------------------
# Linux view 4: sockets with no owner
# ---------------------------------------------------------------------------

def orphan_sockets():
    """Socket inodes bound to a connection that no visible process holds an fd
    for. Under-privileged scans see plenty of these (you cannot read another
    user's fd table), so this is only reported when we are root."""
    from .collect_linux import _socket_table

    table = _socket_table()
    claimed = set()
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            for fd in os.listdir(fddir):
                try:
                    target = os.readlink(f"{fddir}/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:["):
                    claimed.add(int(target[8:-1]))
        except OSError:
            continue

    orphans = []
    for inode, conn in table.items():
        if inode in claimed or inode == 0:
            continue
        if conn["state"] in ("TIME_WAIT", "CLOSE"):
            continue  # kernel-owned leftovers, no process behind them
        orphans.append(conn)
    return orphans


# ---------------------------------------------------------------------------
# Linux view 5: bind() probing for hidden listeners
# ---------------------------------------------------------------------------

def hidden_listeners(limit=10000):
    """Ports the kernel says are taken but /proc/net does not admit to.

    A rootkit that filters /proc/net/tcp still cannot make the kernel hand out a
    port that is genuinely bound. Asking to bind it and being refused with
    EADDRINUSE, while no visible socket claims it, means something is listening
    that does not want to be seen.
    """
    import socket as _s

    table = _socket_table_safe()
    visible = {c["local_port"] for c in table.values()}
    found = []
    for port in range(1, limit + 1):
        if port in visible:
            continue
        sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        try:
            # No SO_REUSEADDR: we want an honest answer about the port.
            sock.bind(("0.0.0.0", port))
        except PermissionError:
            continue  # privileged port and we are not root; inconclusive
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                found.append(port)
            continue
        finally:
            sock.close()
    return found


def _socket_table_safe():
    from .collect_linux import _socket_table
    try:
        return _socket_table()
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Linux view 6: kernel modules, eBPF and function hooking
# ---------------------------------------------------------------------------

def hidden_modules():
    """Modules the kernel has loaded but /proc/modules omits.

    A classic LKM rootkit unlinks itself from the module list, but the sysfs
    directory it created on load usually survives the trick.
    """
    listed = set()
    for line in _read("/proc/modules").splitlines():
        if line.split():
            listed.add(line.split()[0])

    hidden = []
    try:
        for name in os.listdir("/sys/module"):
            # Built-in modules have no initstate; only genuinely loaded ones do.
            state = _read(f"/sys/module/{name}/initstate").strip()
            if state == "live" and name not in listed:
                hidden.append(name)
    except OSError:
        pass
    return hidden


def bpf_programs():
    """Loaded eBPF programs and the processes holding eBPF file descriptors.

    eBPF is now the preferred way to build a Linux rootkit: it loads on any
    modern kernel without matching kernel headers, and it can filter what other
    tools see. Legitimate users exist (systemd, docker, observability agents),
    so this is inventory to review, not an accusation.
    """
    progs, holders = [], []

    out = _run_capture(["bpftool", "--json", "prog", "list"])
    if out:
        try:
            import json as _json
            for p in _json.loads(out):
                progs.append({
                    "id": p.get("id"), "type": p.get("type"),
                    "name": p.get("name") or "(unnamed)",
                    "tag": p.get("tag", ""), "pids": p.get("pids", []),
                })
        except Exception:
            pass

    # Even without bpftool, a process holding a bpf fd is visible in its fd table.
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        fddir = f"{PROC}/{entry}/fd"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        kinds = set()
        for fd in fds:
            try:
                target = os.readlink(f"{fddir}/{fd}")
            except OSError:
                continue
            if "bpf-prog" in target or "bpf-map" in target or "bpf_link" in target:
                kinds.add(target.split(":")[-1].strip("[]"))
        if kinds:
            holders.append({"pid": int(entry), "name": _describe(int(entry))["name"],
                            "kinds": sorted(kinds)})
    return progs, holders


def ftrace_hooks():
    """Kernel functions currently hooked via ftrace — how many rootkits patch
    syscalls without touching the syscall table itself."""
    for path in ("/sys/kernel/tracing/enabled_functions",
                 "/sys/kernel/debug/tracing/enabled_functions"):
        body = _read(path).strip()
        if body:
            return [l.split()[0] for l in body.splitlines() if l.strip()][:40]
    return []


def _run_capture(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---------------------------------------------------------------------------
# Linux view 7: injected and fileless code in live processes
# ---------------------------------------------------------------------------

def injected_processes():
    """Processes running code with no honest file behind it.

    Three shapes worth catching:
      LD_PRELOAD in a live environment  -- userland hooking of that process
      an executable mapping marked (deleted) -- the file was unlinked after load
      a memfd: executable mapping -- fileless execution, never touched the disk
    """
    hits = []
    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        pid = int(entry)
        reasons = []

        environ = _read(f"{PROC}/{pid}/environ", binary=True)
        if b"LD_PRELOAD=" in environ:
            val = ""
            for part in environ.split(b"\x00"):
                if part.startswith(b"LD_PRELOAD="):
                    val = part.decode("utf-8", "replace")[11:]
            if val:
                reasons.append(("LD_PRELOAD set", val))

        maps = _read(f"{PROC}/{pid}/maps")
        for line in maps.splitlines():
            if len(line.split()) < 6:
                continue
            perms, path = line.split()[1], line.split(None, 5)[5]
            if "x" not in perms:
                continue
            if path.endswith("(deleted)"):
                reasons.append(("executable mapping was deleted from disk", path))
                break
            if path.startswith("/memfd:"):
                reasons.append(("fileless executable mapping (memfd)", path))
                break

        if reasons:
            info = _describe(pid)
            hits.append({"pid": pid, "name": info["name"],
                         "cmdline": info["cmdline"] or info["exe"],
                         "reasons": reasons})
    return hits


def _read(path, binary=False):
    try:
        if binary:
            with open(path, "rb") as fh:
                return fh.read()
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return b"" if binary else ""


# ---------------------------------------------------------------------------
# Linux: /proc overmount hiding
# ---------------------------------------------------------------------------

def proc_overmounts():
    """A bind-mount over /proc/<pid> makes a process unreadable without any
    code injection at all."""
    hits = []
    try:
        with open("/proc/self/mountinfo", errors="replace") as fh:
            for line in fh:
                f = line.split()
                if len(f) > 4 and re.match(r"^/proc/\d+", f[4]):
                    hits.append(f[4])
    except OSError:
        pass
    return hits


def audit_linux(deep=False):
    out = []
    sweep_limit = pid_max() if deep else min(DEFAULT_SWEEP, pid_max())

    readdir = view_readdir()
    getdents = view_getdents()
    swept = view_stat_sweep(sweep_limit)

    # Anything the sweep can stat but the listing omitted. Re-verify, because a
    # process that simply exited between the two passes looks identical here.
    suspects = sorted(swept - readdir)
    confirmed = []
    if suspects:
        time.sleep(0.35)
        fresh = view_readdir()
        for pid in suspects:
            if _alive(pid) and pid not in fresh and not is_thread(pid):
                confirmed.append(pid)

    for pid in confirmed:
        info = _describe(pid)
        out.append(_finding(
            "critical", "process hidden from /proc listing",
            f"pid {pid} ({info['name']}) resolves by direct stat() but is absent "
            f"from readdir — {info['cmdline'] or info['exe'] or 'no cmdline'}",
            f"uid={info['uid']} ppid={info['ppid']} exe={info['exe'] or '?'}",
        ))

    if getdents is None:
        out.append(_finding("low", "syscall view unavailable",
                            "could not call getdents64 directly on this ABI; "
                            "libc-hook detection was skipped", os.uname().machine))
    else:
        # libc says fewer pids than the kernel does -> something is hooking libc.
        hooked = sorted(getdents - readdir)
        for pid in hooked:
            if _alive(pid) and not is_thread(pid):
                info = _describe(pid)
                out.append(_finding(
                    "critical", "process hidden from libc but visible to the kernel",
                    f"pid {pid} ({info['name']}) appears in raw getdents64 output "
                    f"but not through libc readdir — this is the signature of an "
                    f"LD_PRELOAD rootkit",
                    info["cmdline"] or info["exe"],
                ))

    for path in proc_overmounts():
        out.append(_finding("critical", "/proc entry is bind-mounted over",
                            f"{path} is masked by a mount, hiding that process",
                            "/proc/self/mountinfo"))

    # -- hidden listeners --------------------------------------------------
    port_limit = 65535 if deep else 10000
    for port in hidden_listeners(port_limit):
        out.append(_finding(
            "critical", "port is bound but no socket admits to it",
            f"tcp/{port} refuses a bind with EADDRINUSE, yet nothing in "
            f"/proc/net claims it — a filtered socket table",
            f"bind probe 1–{port_limit}"))

    # -- kernel modules ----------------------------------------------------
    for mod in hidden_modules():
        out.append(_finding(
            "critical", "kernel module hidden from /proc/modules",
            f"{mod} is live in sysfs but unlisted — the signature of an LKM "
            f"rootkit unlinking itself", f"/sys/module/{mod}"))

    # -- eBPF --------------------------------------------------------------
    progs, holders = bpf_programs()
    for p in progs:
        risky = (p.get("type") or "") in (
            "kprobe", "tracepoint", "raw_tracepoint", "lsm", "fentry", "fexit")
        out.append(_finding(
            "medium" if risky else "low", "eBPF program loaded",
            f"{p['name']} [{p.get('type')}] id={p.get('id')}"
            + (f" pids={[x.get('pid') for x in p['pids']]}" if p.get("pids") else ""),
            "bpftool prog list"))
    for h in holders:
        out.append(_finding("low", "process holds eBPF handles",
                            f"{h['name']} [pid {h['pid']}] — {', '.join(h['kinds'])}",
                            f"/proc/{h['pid']}/fd"))

    hooks = ftrace_hooks()
    if hooks:
        out.append(_finding(
            "high", "kernel functions are hooked via ftrace",
            f"{len(hooks)} hooked: {', '.join(hooks[:6])}"
            + ("…" if len(hooks) > 6 else ""),
            "/sys/kernel/tracing/enabled_functions"))

    # -- injected / fileless code -----------------------------------------
    for hit in injected_processes():
        worst = max(("fileless" in r[0]) * 2 + ("deleted" in r[0]) for r in hit["reasons"])
        out.append(_finding(
            "critical" if worst else "high",
            hit["reasons"][0][0],
            f"{hit['name']} [pid {hit['pid']}] — {hit['reasons'][0][1][:80]}",
            hit["cmdline"][:120]))

    if os.geteuid() == 0:
        for conn in orphan_sockets():
            out.append(_finding(
                "high", "network connection with no owning process",
                f"{conn['proto']} {conn['local_ip']}:{conn['local_port']} → "
                f"{conn['remote_ip']}:{conn['remote_port']} ({conn['state']}) "
                f"is not claimed by any visible process",
                "/proc/net + fd sweep",
            ))

    out.append(_finding("ok", "cross-view scan complete",
                        f"{len(readdir)} pids via readdir, "
                        f"{len(getdents) if getdents is not None else '—'} via getdents64, "
                        f"{len(swept)} via stat sweep (1–{sweep_limit})",
                        ""))
    for f in out:
        f["host"] = "wsl"
    return out


# ---------------------------------------------------------------------------
# Windows cross-view
# ---------------------------------------------------------------------------

PS_HIDDEN = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.wmi      = @(Get-CimInstance Win32_Process | ForEach-Object {
                  [pscustomobject]@{ pid=$_.ProcessId; name=$_.Name; path=$_.ExecutablePath } })
$o.api      = @(Get-Process | ForEach-Object {
                  [pscustomobject]@{ pid=$_.Id; name=$_.ProcessName; path=$_.Path;
                                     title=$_.MainWindowTitle } })
$o.tasklist = @((tasklist /fo csv /nh 2>$null) -split "`n" | Where-Object { $_ -match '^"' } |
                  ForEach-Object { $p = $_ -split '","'
                                   [pscustomobject]@{ name=$p[0].Trim('"'); pid=[int]($p[1]) } })
$o.netpids  = @((Get-NetTCPConnection).OwningProcess | Sort-Object -Unique)

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""


def _aslist(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def audit_windows():
    data = _ps_json(PS_HIDDEN, timeout=120)
    if data is None:
        return [_finding("medium", "Windows cross-view unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    wmi = {p["pid"]: p for p in _aslist(data.get("wmi")) if p.get("pid") is not None}
    api = {p["pid"]: p for p in _aslist(data.get("api")) if p.get("pid") is not None}
    tl = {p["pid"]: p for p in _aslist(data.get("tasklist")) if p.get("pid") is not None}
    netpids = {p for p in _aslist(data.get("netpids")) if isinstance(p, int) and p > 4}

    def label(pid):
        for src in (wmi, api, tl):
            if pid in src:
                return src[pid].get("name") or "?"
        return "unknown"

    # WMI and the process API disagreeing is the classic userland-hook tell.
    for pid in sorted(set(wmi) - set(api) - {0, 4}):
        out.append(_finding("high", "process visible to WMI but not to the process API",
                            f"pid {pid} ({label(pid)}) — {wmi[pid].get('path') or 'no path'}",
                            "Win32_Process vs Get-Process"))
    for pid in sorted(set(api) - set(wmi) - {0, 4}):
        out.append(_finding("high", "process visible to the process API but not to WMI",
                            f"pid {pid} ({label(pid)}) — WMI provider may be tampered with",
                            "Get-Process vs Win32_Process"))
    for pid in sorted((set(wmi) | set(api)) - set(tl) - {0, 4}):
        out.append(_finding("medium", "process missing from tasklist",
                            f"pid {pid} ({label(pid)})", "tasklist.exe"))

    for pid in sorted(netpids - set(wmi) - set(api) - set(tl)):
        out.append(_finding("critical", "network connection owned by an invisible process",
                            f"pid {pid} holds an open TCP connection but appears in no "
                            f"process listing",
                            "Get-NetTCPConnection vs process views"))

    out.append(_finding("ok", "cross-view scan complete",
                        f"{len(wmi)} via WMI, {len(api)} via process API, "
                        f"{len(tl)} via tasklist", ""))
    for f in out:
        f["host"] = "win"
    return out, data


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def audit(hosts=("wsl", "win"), deep=False):
    out, extra = [], {}
    if "wsl" in hosts:
        out += audit_linux(deep=deep)
    if "win" in hosts:
        res = audit_windows()
        if isinstance(res, tuple):
            out += res[0]
            extra = res[1]
        else:
            out += res
    out.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["title"]))
    return out, extra
