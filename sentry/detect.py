"""Turn raw process records into findings.

Two independent signals combine into one severity:
  1. drift   -- is this fingerprint in the approved baseline?
  2. traits  -- does the process itself look like something you'd worry about?

A known-good process with a bad trait still gets flagged, and an unknown
process with no bad traits stays low-noise. That separation is what keeps a
baseline system from either screaming at every update or going quiet when
something ugly hides behind an approved name.
"""

import os
import re

from .util import classify_ip

# Directories any user can write to, which is where dropped payloads land.
SUSPECT_DIRS = (
    "/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/",
    "\\appdata\\local\\temp\\", "\\downloads\\", "\\windows\\temp\\",
    "\\users\\public\\", "\\programdata\\",
)

RULES = [
    # (id, weight, description) -- weights sum into a severity score
    ("encoded-command", 45, "obfuscated/encoded command line"),
    ("remote-exec-pipe", 45, "downloads and pipes straight into a shell"),
    ("deleted-binary", 40, "executable was deleted while still running"),
    ("no-exe-path", 20, "no resolvable executable path"),
    ("temp-exec", 30, "running from a world-writable directory"),
    ("script-in-temp", 35, "interpreting a script from a temp directory"),
    ("name-mismatch", 25, "process name does not match its executable"),
    ("hidden-name", 20, "leading-dot or whitespace-padded name"),
    ("public-listener", 25, "listening on all interfaces"),
    ("public-egress", 10, "connected to a public internet address"),
    ("root-unknown", 15, "unrecognized process running as root/SYSTEM"),
    ("new-untrusted-binary", 0, "new executable outside standard install paths"),
]
WEIGHT = {r[0]: r[1] for r in RULES}
DESC = {r[0]: r[2] for r in RULES}

ENCODED = re.compile(r"(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,})|"
                     r"(base64\s+(-d|--decode))|"
                     r"(FromBase64String)", re.I)
PIPE_EXEC = re.compile(
    r"(curl|wget|iwr|invoke-webrequest|Invoke-Expression|\biex\b)[^|;]*[|;]\s*"
    r"(ba|z|d)?sh\b|\|\s*(python|perl|node)\b",
    re.I,
)
HIDDEN_NAME = re.compile(r"^[\s.]")

# Package-manager territory. Software here got there through an install, so a
# first sighting means "new invocation", not "new software".
TRUSTED_PATHS = (
    "/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
    "/lib/", "/usr/local/bin/", "/snap/", "/opt/",
    "c:/windows/", "c:/program files/", "c:/program files (x86)/",
)


def from_trusted_path(p: dict) -> bool:
    """True when the executable lives where installed software belongs."""
    script = (p.get("script") or "").lower().replace("\\", "/")
    # A bare script name ("sh -c eslint") says nothing about location; only a
    # real path can vouch for — or condemn — where the code came from.
    target = script if "/" in script else (p.get("exe") or "").lower().replace("\\", "/")
    if not target:
        return False
    return target.startswith(TRUSTED_PATHS)


def _lower_path(p: str) -> str:
    return (p or "").replace("\\", "/").lower().replace("/", "/")


def traits(p: dict) -> list:
    """Reason ids describing what looks wrong about this process, if anything."""
    found = []
    exe = p.get("exe") or ""
    script = p.get("script") or ""
    cmd = p.get("cmdline") or ""
    name = p.get("name") or ""
    exe_l = exe.lower().replace("\\", "/")
    script_l = script.lower().replace("\\", "/")

    if ENCODED.search(cmd):
        found.append("encoded-command")
    if PIPE_EXEC.search(cmd):
        found.append("remote-exec-pipe")
    if exe.endswith(" (deleted)"):
        found.append("deleted-binary")

    norm_dirs = [d.replace("\\", "/") for d in SUSPECT_DIRS]
    if any(d in exe_l for d in norm_dirs):
        found.append("temp-exec")
    if script and any(d in script_l for d in norm_dirs):
        found.append("script-in-temp")

    # Kernel threads legitimately have no exe (they show as [name]), and another
    # user's process is unreadable rather than hidden. Only a real userspace
    # process whose exe link is genuinely gone is worth reporting.
    if (not exe and p["host"] == "wsl" and not cmd.startswith("[")
            and not p.get("exe_hidden")):
        found.append("no-exe-path")

    if exe and name:
        base = os.path.basename(exe_l).removesuffix(".exe")
        nm = name.lower().removesuffix(".exe")
        # Linux truncates comm to 15 chars, so compare on that prefix. Version
        # directories (…/claude/versions/2.1.233) put the real name upstream in
        # the path, so check the whole path before calling it a mismatch.
        if (base[:15] != nm[:15] and nm not in base and base not in nm
                and nm not in exe_l):
            found.append("name-mismatch")

    if HIDDEN_NAME.match(name):
        found.append("hidden-name")

    for c in p.get("conns", []):
        if c.get("state") == "LISTEN" and c.get("local_ip") in ("0.0.0.0", "::", "0000:0000"):
            found.append("public-listener")
            break

    if any(classify_ip(c.get("remote_ip", "")) == "public"
           and c.get("state") not in ("LISTEN", "TIME_WAIT", "CLOSE_WAIT")
           for c in p.get("conns", [])):
        found.append("public-egress")

    return found


def severity(score: int, unknown: bool) -> str:
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15 or unknown:
        return "medium"
    return "low"


def assess(p: dict, known: set, approved: set) -> dict:
    """Full verdict for one process record."""
    fp = p["fp"]
    unknown = fp not in known
    reasons = traits(p)

    if unknown and (p.get("user") in ("root", "SYSTEM")):
        reasons.append("root-unknown")

    score = sum(WEIGHT.get(r, 0) for r in reasons)
    untrusted_path = unknown and not from_trusted_path(p)
    if unknown:
        # A new invocation of /usr/bin/tail is drift worth logging; a new binary
        # running out of your home directory is drift worth waking up for.
        score += 30 if untrusted_path else 12
        if untrusted_path:
            reasons = reasons + ["new-untrusted-binary"]
    # An explicitly approved process gets credit, but traits still carry through.
    if fp in approved:
        score = max(0, score - 12)

    return {
        "unknown": unknown,
        "approved": fp in approved,
        "reasons": reasons,
        "score": score,
        "severity": severity(score, untrusted_path and fp not in approved),
    }


def explain(reasons) -> str:
    return "; ".join(DESC.get(r, r) for r in reasons)
