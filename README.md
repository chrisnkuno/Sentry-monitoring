# sentry

Monitors what runs on this machine — both the WSL2 Linux side and the Windows
host — and audits the ways something could take or keep control of it.

Pure Python 3 standard library. No dependencies, no agent, no network calls
unless you ask for `--enrich`.

## Start here

```bash
cd ~/sentry
./install.sh --service   # run it 24/7, dashboard at http://127.0.0.1:8787
sentry investigate       # or a one-off report in the terminal
```

## The dashboard

`sentry serve` runs a scheduler and a local web page. It is plain
`http.server` + SQLite + one self-contained HTML file — no framework, no build
step, no CDN, and no dependency beyond the Python standard library. For a
security tool that is the point: every dependency is code you have to trust, and
this one is meant to tell you when something untrustworthy is running.

Three things shaped the design:

- **Collectors have wildly different costs.** Reading `/proc` takes 20ms; a
  PowerShell audit takes 10–60s because crossing the WSL interop boundary
  dominates everything else. So each job runs on its own interval — processes
  every 60s, firewall every 15min, spyware and autostart hourly.
- **Jobs never run concurrently.** A single worker runs them one at a time; two
  simultaneous `powershell.exe` launches are slower than running them back to
  back and fight over the same interop pipe.
- **The page never waits for a scan.** Every request is served from the last
  stored snapshot, so the dashboard is instant even mid-audit, and a restart
  redraws immediately from SQLite instead of showing a blank page.

The listener binds `127.0.0.1` with no option to change it. A page listing your
firewall gaps and running processes is exactly what an attacker would like to
read.

### Running 24/7

`./install.sh --service` installs a systemd **user** service with
`Restart=always`. Two WSL-specific gotchas that the installer calls out:

1. **Linger.** Without it, systemd tears down your user manager when your last
   shell exits — closing your terminal would stop the daemon.
   ```bash
   sudo loginctl enable-linger $USER
   ```
2. **WSL itself.** WSL only runs while Windows keeps it running. Run
   `./install.sh --windows` for the one-time PowerShell command that registers a
   hidden logon task to start WSL; systemd and linger take it from there.

## The commands

| command | question it answers |
|---|---|
| `scan` | What is running right now, and is any of it new? |
| `hidden` | Is anything hiding from the normal process listings? |
| `boot` | What ran at startup — including windows that flash open and close? |
| `spy` | Is anything monitoring me? Who used the mic/camera, and when? |
| `firewall` | Who can reach in, and who actually did? |
| `control` | What could take control of this machine, and are the defenses on? |
| `asep` | What else can auto-start code — beyond Run keys? |
| `investigate` | All of the above, in one report. |
| `intrusion` | How would this machine have been broken into — and was it? |
| `serve` | Run everything continuously behind a local dashboard. |

```bash
sentry baseline          # learn the current state as known-good (do this once)
sentry scan              # what drifted, what looks wrong, who it talks to
sentry scan --enrich     # ...and reverse-DNS the public IPs
sentry watch -i 120      # keep scanning, print only medium-and-worse
sentry hidden            # cross-view scan (--deep sweeps the full pid range)
sentry boot              # reconstruct startup from the event logs
sentry spy               # monitoring software, capability use, input devices
sentry firewall          # posture, inbound rules, inbound connections, logons
sentry control -v        # persistence / remote access / defenses
sentry peers --scope public   # every external IP seen, and which process reached it
sentry events --since 24      # alert history
sentry procs --approved 0     # fingerprints not yet approved
sentry approve <fp> --note "my build script"
sentry status
```

Add `--host wsl` or `--host win` to either side alone; the default is both.
Every audit command takes `--severity`, `-v` and `--json`.

## Finding hidden processes

No single process list is trusted, because anything with enough privilege can
lie to the API behind it. `sentry hidden` collects several enumerations that
reach the kernel by different routes and diffs them:

*Linux* — libc `readdir`, the raw `getdents64` syscall via ctypes (which an
`LD_PRELOAD` rootkit cannot filter), a direct `stat()` sweep of the pid range,
and socket inodes that no visible process claims. It also checks for bind-mounts
over `/proc/<pid>`, which hide a process with no code injection at all.

Beyond process listings it looks for the machinery hiding them:

- **Bind probing.** A rootkit that filters `/proc/net/tcp` still cannot make the
  kernel hand out a port that is genuinely bound. Asking to bind each port and
  being refused `EADDRINUSE` while no visible socket claims it means something
  is listening that does not want to be seen.
- **Kernel modules.** A classic LKM rootkit unlinks itself from `/proc/modules`,
  but the `/sys/module/<name>` directory it created on load usually survives.
- **eBPF.** This is now the preferred way to build a Linux rootkit — it loads on
  any modern kernel without matching headers and can filter what other tools
  see. Loaded programs and the processes holding eBPF file descriptors are
  inventoried; tracing-class program types are called out. Legitimate users
  exist (systemd, Docker, observability agents), so this is a list to review.
- **ftrace hooks.** How many rootkits patch syscalls without ever touching the
  syscall table.
- **Injected and fileless code.** `LD_PRELOAD` in a live process environment, an
  executable mapping marked `(deleted)`, or a `memfd:` executable mapping —
  code running with no honest file behind it.

*Windows* — `Win32_Process` (WMI), `Get-Process` (the process API), `tasklist`,
and the pids owning TCP connections. Userland hooks routinely patch one of these
and miss the others. `sentry asep` adds **masquerade detection** (a `svchost.exe`
outside System32 is not svchost) and **parentage analysis** (Office or a browser
spawning a script host, WMI spawning a shell, `lsass` having children at all).

Disagreement between views is re-verified before it is reported, so a process
that merely started or exited mid-scan is not called a rootkit. Threads are
excluded: `/proc/<tid>` stats fine for every thread while `readdir` lists only
thread-group leaders, and treating that as hiding produces nothing but noise.

## Detecting how machines actually get broken into now

`sentry intrusion` targets current initial-access tradecraft rather than
classic malware, because the modern shape is a thing that runs **once** and
leaves no persistent process for a behavioural rule to catch:

- **ClickFix.** A fake CAPTCHA copies a command to your clipboard and tells you
  to press Win+R and paste it — reportedly the largest single initial-access
  technique in circulation. It leaves a perfect fingerprint: Windows records
  everything typed into the Run dialog in `RunMRU`. That key is read and every
  entry matched against download-and-execute shapes.
- **Infostealers.** They harvest browser cookies, session tokens and saved
  passwords, then exit. Detection here is the residue: PowerShell console
  history, recently written unsigned executables in staging directories, and
  browser extensions.
- **Session theft.** Stolen cookies are replayed directly, so the password and
  the second factor never come into it. Extensions are inventoried and rated on
  whether they can read every page and whether they came from outside the store.
- **Defender's own history.** The cheapest question to ask and the one most
  often skipped: has the antivirus already found something and been ignored?
  Detections that were *not* remediated are raised to critical.

## Security of the dashboard itself

Binding to `127.0.0.1` is **not** sufficient on its own. A page you visit can
point a hostname it controls at `127.0.0.1` (DNS rebinding); the browser then
treats it as same-origin with the dashboard and can read every response — which
for this tool is a complete map of the machine's firewall gaps, processes and
external peers. So:

- the `Host` header is validated against an allowlist, which is what actually
  defeats rebinding;
- `/api/run` is POST-only and rejects cross-site requests via `Sec-Fetch-Site`;
- a strict CSP forbids the page from loading anything external.

## Finding commodity spyware

The sophisticated end of this needs a kernel driver to catch. The unsophisticated
end — which is most of it — leaves traces that `sentry spy` reads directly:

- **The capability ledger.** Windows records which application used the
  microphone, camera or location and exactly when, in
  `CapabilityAccessManager\ConsentStore`. Anything recording you through the
  normal APIs appears here, with timestamps.
- **Autostart signatures.** Monitoring tools must survive reboot, and almost
  none are signed by a recognizable publisher. Every autostart binary gets an
  Authenticode check; unsigned *and* in a user-writable directory is the shape
  that matters. Shortcuts are followed to their target first, since a `.lnk`
  carries no signature of its own.
- **Input devices.** Anything that can change your volume or type for you is
  either an HID consumer-control device or software holding an input hook. Both
  are enumerated, deduplicated per physical device.

`sentry asep` covers the persistence surface past Run keys, which is where
anything trying to stay quiet actually lives: `AppInit_DLLs` and Image File
Execution Options debuggers (which inject into *other* processes rather than
starting one of their own), the Winlogon chain, Active Setup, per-user COM
hijacks, LSA packages, print monitors, netsh helpers, time providers, Explorer
extensions, the screensaver, and the `sethc.exe` / `utilman.exe` accessibility
backdoor that runs as SYSTEM from the logon screen before anyone signs in. It
also reads **UserAssist**, Windows' own record of which GUI programs were
launched and how often.

The rule throughout is to flag the **path, not the presence**. Every one of
these extension points is populated on a healthy machine — per-user COM
registrations are how OneDrive and Teams work. What matters is a registration
whose target sits in a world-writable directory, points at a scripting host, or
doesn't exist at all (an empty slot anything could fill).

## Why windows flash open and close at startup

A console window that appears for a fraction of a second is a process with a
console attached that exited immediately — `cmd.exe /c`, `wscript`, a `.bat`, or
PowerShell without `-WindowStyle Hidden`. Interval sampling will never reliably
catch one, so `sentry boot` does not try. It reconstructs the event afterwards
from Task Scheduler's operational log, the autostart inventory filtered to
entries that *would* show a window, and the Application log. Cross-referencing
those usually names the culprit outright.

If the task-history log is empty, enable it once in Task Scheduler → View →
Show All Tasks History, and the next boot will be fully reconstructable.

## How it decides something is unauthorized

Two independent signals combine into one severity, which is what keeps a
baseline system from either screaming at every software update or going quiet
when something hides behind an approved name:

1. **Drift** — the process fingerprint (executable + normalized command line +
   user) is not in the approved baseline. A new invocation of `/usr/bin/tail`
   is logged quietly; a new binary running out of a home or temp directory is
   not.
2. **Traits** — what the process looks like regardless of the baseline:
   encoded command lines, `curl | sh` pipelines, execution from world-writable
   directories, a deleted executable still running, a name that doesn't match
   its binary, listening on all interfaces, egress to public IPs.

A trait on an approved process still gets flagged.

## What it does not do

- It is **not** a kernel-level EDR. It samples on an interval, so a process
  that starts and exits between passes is missed. For gap-free Linux execution
  logging, pair it with `auditd`.
- Without an **elevated PowerShell**, Windows Defender exclusions and some
  service details are unreadable — the audit tells you when this happens rather
  than reporting a clean result it can't actually see.
- WSL is not a security boundary. Anything in WSL can read and write `/mnt/c`,
  and the Windows side can see into WSL. Treat findings on either host as
  findings about one machine.
- Presence of a remote-access agent (TeamViewer, AnyDesk, RMM tooling) is
  reported because it grants control — not because it is necessarily malicious.

## Files

| path | purpose |
|---|---|
| `sentry/collect_linux.py` | `/proc` walker: processes, fds, socket inode → connection |
| `sentry/collect_windows.py` | one-shot PowerShell collector over WSL interop |
| `sentry/detect.py` | trait rules, scoring, severity |
| `sentry/hidden.py` | cross-view enumeration, hidden-process detection |
| `sentry/spyware.py` | capability ledger, autostart signatures, input devices |
| `sentry/startup.py` | boot reconstruction, window-flash attribution |
| `sentry/firewall.py` | firewall posture, inbound rules and connections, logons |
| `sentry/asep.py` | autostart extensibility points, masquerade + parentage |
| `sentry/control.py` | persistence / remote-access / defense audit |
| `sentry/monitor.py` | scan orchestration |
| `sentry/server.py` | scheduler + localhost dashboard server |
| `sentry/static/dashboard.html` | the dashboard, self-contained |
| `sentry/store.py` | SQLite baseline, peers, events |
| `sentry/cli.py` | command-line interface |

State lives in `~/.sentry/sentry.db`.
