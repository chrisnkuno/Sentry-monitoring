"""The always-on half: a scheduler that keeps auditing, and a local dashboard.

Design constraints that shaped this:

  * The collectors have wildly different costs. Reading /proc takes 20ms; a
    PowerShell audit takes 15-60s because crossing the WSL interop boundary and
    spinning up powershell.exe dominates everything else. So jobs run on their
    own intervals, and never concurrently -- a single worker thread runs them
    one at a time, because two simultaneous powershell.exe launches are slower
    than running them back to back and would fight over the same interop pipe.

  * The page must never wait for a scan. Every request is served from the last
    stored snapshot, so the dashboard is instant even while a 60-second Windows
    audit is running behind it.

  * Nothing binds beyond localhost. A dashboard listing your firewall gaps and
    running processes is exactly what an attacker would like to read, so the
    listener is 127.0.0.1 and there is no option to change that to 0.0.0.0.
"""

import json
import os
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import control, firewall, hidden, monitor, spyware, startup
from . import asep as asep_mod
from . import intrusion as intrusion_mod
from .store import DEFAULT_DB, Store
from .util import now

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "static", "dashboard.html")

# name -> (interval seconds, label, callable(hosts) -> list[finding])
JOBS = {
    "scan":     (60,    "Processes & network"),
    "hidden":   (300,   "Hidden processes"),
    "firewall": (900,   "Firewall & inbound"),
    "control":  (1800,  "Control surfaces"),
    "asep":     (3600,  "Autostart points"),
    "spy":      (3600,  "Spyware & capabilities"),
    "intrusion":(1800,  "Intrusion artifacts"),
    "boot":     (21600, "Startup analysis"),
}


def _run_job(name, hosts):
    """Run one audit and return its findings in the common shape."""
    if name == "scan":
        # The process scan is stateful (it maintains the baseline), so it needs
        # its own store handle inside the worker thread.
        store = Store(_run_job.db_path)
        try:
            res = monitor.scan(store, hosts=hosts)
            out = []
            for f in res["findings"]:
                remotes = ", ".join(
                    f"{r['ip']}:{r['port']}" for r in f["remotes"][:3]
                    if r["scope"] == "public")
                out.append({
                    "category": "process", "severity": f["severity"],
                    "host": f["host"],
                    "title": f"{f['name']} [pid {f['pid']}]"
                             + (" — NEW" if f["unknown"] else ""),
                    "detail": (f["cmdline"] or "")[:160]
                              + (f"  →  {remotes}" if remotes else ""),
                    "where": f["exe"] or f.get("script") or "",
                })
            for p in res["new_public_peers"]:
                out.append({
                    "category": "peer", "severity": "medium",
                    "host": p["proc"]["host"],
                    "title": "new external peer",
                    "detail": f"{p['ip']}:{p['port']} ← {p['proc']['name']}",
                    "where": p["proc"].get("exe") or "",
                })
            return out
        finally:
            store.close()

    if name == "hidden":
        return hidden.audit(hosts=hosts)[0]
    if name == "firewall":
        return firewall.audit(hosts=hosts)
    if name == "control":
        return control.audit(hosts=hosts)
    if name == "asep":
        return asep_mod.sort_findings(asep_mod.audit())
    if name == "spy":
        return spyware.sort_findings(spyware.audit())
    if name == "intrusion":
        return intrusion_mod.sort_findings(intrusion_mod.audit())
    if name == "boot":
        return startup.sort_findings(startup.audit())
    raise ValueError(name)


class Scheduler(threading.Thread):
    """Runs the audits forever, one at a time, each on its own interval."""

    daemon = True

    def __init__(self, db_path, hosts):
        super().__init__(name="sentry-scheduler")
        self.db_path = db_path
        self.hosts = hosts
        self.next_run = {name: 0.0 for name in JOBS}   # 0 => run immediately
        self.forced = []
        self.current = None
        self.lock = threading.Lock()
        _run_job.db_path = db_path

    def force(self, name):
        if name in JOBS:
            with self.lock:
                self.forced.append(name)
            return True
        return False

    def _due(self):
        with self.lock:
            if self.forced:
                return self.forced.pop(0)
        soonest, when = None, None
        for name, t in self.next_run.items():
            if t <= time.time() and (when is None or t < when):
                soonest, when = name, t
        return soonest

    def run(self):
        store = Store(self.db_path)
        try:
            while True:
                name = self._due()
                if name is None:
                    time.sleep(1)
                    continue
                self.current = name
                started = time.time()
                try:
                    findings = _run_job(name, self.hosts)
                    store.save_snapshot(name, findings, max(0.0, time.time() - started))
                except Exception:
                    # One broken collector must never stop the other six.
                    store.save_snapshot(name, [], max(0.0, time.time() - started),
                                        traceback.format_exc()[-800:])
                finally:
                    self.current = None
                    self.next_run[name] = time.time() + JOBS[name][0]
        finally:
            store.close()


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def build_state(db_path, scheduler):
    store = Store(db_path)
    try:
        snaps = store.get_snapshots()
        jobs, all_findings = [], []
        for name, (interval, label) in JOBS.items():
            s = snaps.get(name)
            counts = {}
            if s:
                for f in s["findings"]:
                    sev = f.get("severity")
                    if sev and sev != "ok":
                        counts[sev] = counts.get(sev, 0) + 1
                for f in s["findings"]:
                    if f.get("severity") != "ok":
                        all_findings.append({**f, "job": name})
            jobs.append({
                "name": name, "label": label, "interval": interval,
                "ts": s["ts"] if s else 0,
                "duration": round(s["duration"], 1) if s else 0,
                "error": (s["error"] or "")[:400] if s else "",
                "counts": counts,
                "running": scheduler.current == name,
                "next": int(scheduler.next_run.get(name, 0) - time.time()),
            })

        all_findings.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9),
                                         f.get("job", "")))
        worst = all_findings[0]["severity"] if all_findings else "ok"
        totals = {}
        for f in all_findings:
            totals[f["severity"]] = totals.get(f["severity"], 0) + 1

        return {
            "now": now(),
            "worst": worst,
            "totals": totals,
            "jobs": jobs,
            "findings": all_findings[:400],
            "history": store.get_history(24),
            "peers": [dict(r) for r in store.list_peers(scope="public", limit=25)],
            "baseline_at": store.get_meta("baseline_at"),
            "db": db_path,
        }
    finally:
        store.close()


# Binding to 127.0.0.1 is NOT sufficient on its own. A malicious page you visit
# can point a hostname it controls at 127.0.0.1 (DNS rebinding); the browser then
# treats that hostname as same-origin with this server and can read every
# response — which for this tool means handing over a complete map of the
# machine's firewall gaps, running processes and external peers. The defence is
# to check the Host header and serve only names we expect.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


class Handler(BaseHTTPRequestHandler):
    server_version = "sentry"
    db_path = DEFAULT_DB
    scheduler = None

    def log_message(self, *a):
        pass  # the dashboard polls constantly; access logs would be noise

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        # Strip the port; ports are not part of the rebinding decision.
        if host.startswith("["):                      # bracketed IPv6 literal
            name = host[: host.index("]") + 1] if "]" in host else host
        else:
            name = host.rsplit(":", 1)[0] if ":" in host else host
        return name.lower() in ALLOWED_HOSTS

    def _same_origin(self):
        """Reject cross-site calls. Browsers that send Sec-Fetch-Site make this
        exact; for anything older we fall back to checking Origin."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site in ("same-origin", "none")
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl and friends send no Origin at all
        return any(origin == f"http://{h}:{self.server.server_address[1]}"
                   for h in ("localhost", "127.0.0.1"))

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The page is entirely self-contained; forbid anything external.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, json.dumps({"error": "bad host"}))
        if not self._same_origin():
            return self._send(403, json.dumps({"error": "cross-site request"}))
        url = urlparse(self.path)
        if url.path == "/api/run":
            job = (parse_qs(url.query).get("job") or [""])[0]
            ok = self.scheduler.force(job)
            return self._send(200 if ok else 404, json.dumps({"queued": ok}))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "forbidden: unexpected Host header\n"
                                   "reach this dashboard as http://localhost:PORT",
                              "text/plain")
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            try:
                with open(PAGE, "r", encoding="utf-8") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(500, "dashboard.html missing", "text/plain")

        if url.path == "/api/state":
            return self._send(200, json.dumps(
                build_state(self.db_path, self.scheduler), default=str))

        # /api/run is a state-changing action, so it is POST-only: a cross-site
        # page cannot force one without a preflight it will not survive.
        if url.path == "/api/run":
            return self._send(405, json.dumps({"error": "use POST"}))

        return self._send(404, json.dumps({"error": "not found"}))


def serve(db_path=DEFAULT_DB, port=8787, hosts=("wsl", "win")):
    scheduler = Scheduler(db_path, hosts)
    scheduler.start()

    Handler.db_path = db_path
    Handler.scheduler = scheduler
    # Localhost only, deliberately and without an override.
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # flush=True so journalctl shows these immediately under systemd, where
    # stdout is a pipe and would otherwise stay buffered indefinitely.
    print(f"sentry dashboard  \u2192  http://127.0.0.1:{port}", flush=True)
    print(f"  watching {'+'.join(hosts)};  database {db_path}", flush=True)
    print("  jobs: " + ", ".join(f"{n} every {v[0]}s" for n, v in JOBS.items()),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
