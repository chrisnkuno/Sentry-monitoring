"""Shared helpers: fingerprinting, IP classification, time."""

import hashlib
import ipaddress
import re
import socket
import time

# Values that legitimately change between runs of the same program. Collapsing
# them keeps a process's fingerprint stable so restarts don't look like drift.
_VOLATILE = [
    (re.compile(r"/tmp/[^\s]*"), "/tmp/<tmp>"),
    (re.compile(r"/proc/\d+"), "/proc/<pid>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\b\d{4,}\b"), "<num>"),
    (re.compile(r"\s+"), " "),
]


def normalize_cmdline(cmdline: str) -> str:
    out = cmdline.strip()
    for pat, repl in _VOLATILE:
        out = pat.sub(repl, out)
    return out.strip()


def fingerprint(host: str, exe: str, cmdline: str, user: str) -> str:
    """Stable identity for 'this program, run this way, by this user'."""
    raw = "\x00".join([host, exe or "", normalize_cmdline(cmdline), user or ""])
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def now() -> int:
    return int(time.time())


def iso(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def classify_ip(ip: str) -> str:
    """Bucket an address so public egress stands out from local chatter."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_private:
        return "private"
    return "public"


_rdns_cache: dict[str, str] = {}


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    """Best-effort PTR lookup. Only called when --enrich is passed."""
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ""
    finally:
        socket.setdefaulttimeout(old)
    _rdns_cache[ip] = name
    return name


def short(text: str, width: int = 70) -> str:
    text = (text or "").replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"
