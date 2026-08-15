"""Collect processes and their sockets from /proc. Stdlib only, no root needed.

Without root you see full detail for your own processes and names/cmdlines for
everyone else's; sockets owned by other users resolve to the process only if we
can read their fd table.
"""

import os
import pwd
import re

from .util import fingerprint

PROC = "/proc"
HOST = "wsl"

# Interpreters whose real identity is the script they were handed, not the binary.
INTERPRETERS = re.compile(
    r"^(python[\d.]*|perl|ruby|node|bash|sh|dash|zsh|ksh|php|lua|Rscript|deno|bun)$"
)
SCRIPT_EXT = re.compile(r"\.(py|sh|pl|rb|js|mjs|cjs|ts|php|lua|R|bash|zsh)$", re.I)


def _read(path, binary=False):
    try:
        if binary:
            with open(path, "rb") as fh:
                return fh.read()
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return b"" if binary else ""


def _uid_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _parse_addr(hexaddr):
    """/proc/net/* encodes addresses as little-endian hex words."""
    host, _, port = hexaddr.rpartition(":")
    port = int(port, 16)
    raw = bytes.fromhex(host)
    if len(raw) == 4:
        ip = ".".join(str(b) for b in raw[::-1])
    elif len(raw) == 16:
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        flat = b"".join(words)
        parts = [f"{flat[i]<<8 | flat[i+1]:x}" for i in range(0, 16, 2)]
        ip = ":".join(parts)
        # Render v4-mapped addresses (::ffff:a.b.c.d) in their familiar form.
        if parts[:6] == ["0", "0", "0", "0", "0", "ffff"]:
            ip = ".".join(str(b) for b in flat[12:16])
    else:
        ip = host
    return ip, port


TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def _socket_table():
    """inode -> connection detail, built from all four /proc/net socket tables."""
    table = {}
    for fname, proto in (("tcp", "tcp"), ("tcp6", "tcp6"), ("udp", "udp"), ("udp6", "udp6")):
        text = _read(f"{PROC}/net/{fname}")
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                continue
            try:
                lip, lport = _parse_addr(f[1])
                rip, rport = _parse_addr(f[2])
                inode = int(f[9])
            except (ValueError, IndexError):
                continue
            table[inode] = {
                "proto": proto,
                "local_ip": lip,
                "local_port": lport,
                "remote_ip": rip,
                "remote_port": rport,
                "state": TCP_STATES.get(f[3].upper(), f[3]) if proto.startswith("tcp") else "-",
            }
    return table


def _proc_sockets(pid, table):
    """Map a pid's socket fds back to the connection table."""
    conns = []
    fddir = f"{PROC}/{pid}/fd"
    try:
        fds = os.listdir(fddir)
    except (OSError, PermissionError):
        return conns
    for fd in fds:
        try:
            target = os.readlink(f"{fddir}/{fd}")
        except OSError:
            continue
        if target.startswith("socket:["):
            inode = int(target[8:-1])
            if inode in table:
                conns.append(table[inode])
    return conns


def _script_target(argv, exe_base):
    """For an interpreter, return the script path it is actually executing."""
    if not INTERPRETERS.match(exe_base):
        return ""
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        if SCRIPT_EXT.search(arg) or "/" in arg:
            return arg
        return arg
    return ""


def collect(with_sockets=True):
    """Return a list of process records for the Linux side."""
    table = _socket_table() if with_sockets else {}
    procs = []
    self_pid = os.getpid()

    for entry in os.listdir(PROC):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == self_pid:
            continue
        base = f"{PROC}/{pid}"

        raw = _read(f"{base}/cmdline", binary=True)
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\x00") if a]
        status = _read(f"{base}/status")
        if not status:
            continue  # process exited mid-scan

        name = ""
        uid = -1
        ppid = 0
        for line in status.splitlines():
            if line.startswith("Name:"):
                name = line.split("\t", 1)[-1].strip()
            elif line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("PPid:"):
                ppid = int(line.split()[1])

        # Distinguish "no exe" (kernel thread / deleted binary — interesting)
        # from "can't read it" (another user's process — not our business).
        exe, exe_hidden = "", False
        try:
            exe = os.readlink(f"{base}/exe")
        except PermissionError:
            exe_hidden = True
        except OSError:
            pass

        cmdline = " ".join(argv) if argv else f"[{name}]"
        exe_base = os.path.basename(exe or name)
        script = _script_target(argv, exe_base)

        # A python script's identity is the script, not /usr/bin/python3.
        ident_exe = script if script else exe

        procs.append({
            "host": HOST,
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "exe": exe,
            "exe_hidden": exe_hidden,
            "script": script,
            "cmdline": cmdline,
            "user": _uid_name(uid),
            "conns": _proc_sockets(pid, table) if with_sockets else [],
            "fp": fingerprint(HOST, ident_exe or name, cmdline, _uid_name(uid)),
        })

    return procs
