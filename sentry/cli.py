"""Command-line interface for sentry."""

import argparse
import json
import sys
import time

from . import (asep, collect_windows, control, detect, firewall, hidden,
               intrusion, monitor, spyware, startup)
from .store import DEFAULT_DB, Store
from .util import iso, now, short

C = {
    "critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
    "low": "\033[90m", "ok": "\033[32m", "dim": "\033[90m", "bold": "\033[1m",
    "reset": "\033[0m",
}


def color(text, key, on=True):
    return f"{C[key]}{text}{C['reset']}" if on and key in C else text


def _tty():
    return sys.stdout.isatty()


def _hosts(args):
    if args.host == "all":
        return ("wsl", "win")
    return (args.host,)


# ---------------------------------------------------------------------------


def cmd_baseline(args, store):
    if args.reset:
        store.db.execute("DELETE FROM procs")
        store.db.execute("DELETE FROM peers")
        store.commit()
        print("Cleared the previous baseline.")
    print("Learning the current state as your known-good baseline…")
    res = monitor.scan(store, hosts=_hosts(args), enrich=False, learn=True)
    store.set_meta("baseline_at", now())
    total = len(store.known_fps())
    print(f"  {res['scanned']} processes captured, {total} unique fingerprints approved.")
    print(f"  Database: {store.path}")
    print("\nFrom now on, anything new shows up as drift. Re-run `sentry baseline` "
          "after you install software you trust — it adds to what's already there.")


def cmd_scan(args, store):
    if not store.get_meta("baseline_at"):
        print(color("No baseline yet — everything will look new. "
                    "Run `sentry baseline` first.\n", "medium", _tty()))
    res = monitor.scan(store, hosts=_hosts(args), enrich=args.enrich)

    if args.json:
        print(json.dumps(res, default=str, indent=2))
        return

    print(monitor.summarize(res))
    findings = res["findings"]
    if args.severity:
        keep = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.severity]
        findings = [f for f in findings if monitor.SEV_ORDER[f["severity"]] <= keep]

    if not findings:
        print(color("  no drift, no suspicious traits.", "ok", _tty()))
    for f in findings[: args.limit]:
        _print_finding(f)

    if res["new_public_peers"]:
        print(f"\n{color('New external peers', 'bold', _tty())} "
              f"({len(res['new_public_peers'])} first-time public IPs):")
        for p in res["new_public_peers"][: args.limit]:
            proc = p["proc"]
            rd = f"  {p.get('rdns')}" if p.get("rdns") else ""
            print(f"  {p['ip']}:{p['port']}  ←  {proc['name']} "
                  f"[{proc['host']}/{proc['pid']}]{rd}")

    if len(findings) > args.limit:
        print(f"\n  … {len(findings) - args.limit} more (use --limit)")


def _print_finding(f):
    t = _tty()
    sev = f["severity"]
    tag = color(f" {sev.upper():8} ", sev, t)
    flag = "NEW" if f["unknown"] else "   "
    print(f"\n{tag} {flag} {color(f['name'], 'bold', t)} "
          f"[{f['host']}/{f['pid']}] {color(f['user'] or '-', 'dim', t)}")
    print(f"          exe   {short(f['exe'] or f.get('script') or '-', 96)}")
    print(f"          cmd   {short(f['cmdline'], 96)}")
    if f["reasons"]:
        print(f"          why   {detect.explain(f['reasons'])}")
    for r in f["remotes"][:6]:
        rd = f"  ({r['rdns']})" if r.get("rdns") else ""
        mark = color("→ PUBLIC", "high", t) if r["scope"] == "public" else "→"
        print(f"          net   {mark} {r['ip']}:{r['port']} "
              f"{r['proto']}/{r['state']}{rd}")
    print(f"          fp    {f['fp']}")


def cmd_watch(args, store):
    print(f"Watching every {args.interval}s — Ctrl-C to stop.  "
          f"(hosts: {'+'.join(_hosts(args))})")
    if args.interval < 30 and "win" in _hosts(args):
        print(color("  note: Windows collection takes a few seconds per pass; "
                    "intervals under 30s will lag.", "dim", _tty()))
    try:
        while True:
            res = monitor.scan(store, hosts=_hosts(args), enrich=args.enrich)
            alerts = [f for f in res["findings"]
                      if monitor.SEV_ORDER[f["severity"]] <= 2]  # medium and worse
            if alerts or res["new_public_peers"]:
                print("\n" + monitor.summarize(res))
                for f in alerts[: args.limit]:
                    _print_finding(f)
                for p in res["new_public_peers"][:10]:
                    print(f"          new peer {p['ip']}:{p['port']} ← "
                          f"{p['proc']['name']}")
            elif args.verbose:
                print(monitor.summarize(res))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")


def cmd_control(args, store):
    print(f"Auditing control surfaces on {'+'.join(_hosts(args))}…\n")
    findings = control.audit(hosts=_hosts(args))

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    if args.category:
        findings = [f for f in findings if f["category"] == args.category]
    if args.severity:
        keep = control.SEV_ORDER[args.severity]
        findings = [f for f in findings if control.SEV_ORDER[f["severity"]] <= keep]

    t = _tty()
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    last_cat = None
    for f in findings:
        if f["category"] != last_cat:
            titles = {
                "persistence": "PERSISTENCE — things arranged to run without you",
                "remote": "REMOTE CONTROL — ways in from outside",
                "defense": "DEFENSES — the state of the controls themselves",
            }
            print(f"\n{color(titles.get(f['category'], f['category']), 'bold', t)}")
            last_cat = f["category"]
        tag = color(f" {f['severity'][:4].upper():4} ", f["severity"], t)
        print(f"  {tag} [{f['host']}] {f['title']}: {f['detail']}")
        if args.verbose and f["where"]:
            print(f"          {color(f['where'], 'dim', t)}")

    tally = "  ".join(f"{k}={counts[k]}" for k in
                      ("critical", "high", "medium", "low") if k in counts)
    print(f"\n{len(findings)} findings   {tally or 'none'}")
    if not args.verbose:
        print(color("  (-v shows the exact location of each item)", "dim", t))


SECTION = {
    # module category -> heading shown above that group
    "spyware": "MONITORING SOFTWARE — things built to watch you",
    "access": "DEVICE & ACCOUNT ACCESS — mic, camera, logons",
    "input": "INPUT & AUDIO CONTROL — what can move your volume or type for you",
    "signing": "AUTOSTART CODE SIGNING — who vouches for what starts with Windows",
    "av": "ANTIVIRUS — what Defender already found",
    "clickfix": "PASTED COMMANDS — the Run dialog and PowerShell history",
    "extension": "BROWSER EXTENSIONS — what can read your sessions",
    "staging": "STAGED FILES — recent unsigned executables",
    "loader": "LOADER ABUSE — code injected into other processes",
    "logon": "LOGON CHAIN",
    "com": "COM REGISTRATIONS",
    "privileged": "PRIVILEGED PLUMBING — code loaded by system services",
    "masquerade": "MASQUERADING & PARENTAGE",
    "history": "EXECUTION HISTORY",
    "flash": "WINDOW FLASHES — autostart entries that show a console window",
    "ran": "WHAT ACTUALLY RAN THIS BOOT",
    "boot": "BOOT",
    "inbound": "INBOUND CONNECTIONS — traffic initiated from outside",
    "rules": "FIREWALL RULES",
    "posture": "FIREWALL POSTURE",
}


def _report(findings, verbose=False, severity=None, sev_order=None,
            show_ok=False, empty="nothing found"):
    """Shared renderer for the audit-style commands."""
    t = _tty()
    sev_order = sev_order or {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    if severity:
        findings = [f for f in findings
                    if sev_order.get(f["severity"], 9) <= sev_order[severity]]
    if not show_ok and not verbose:
        findings = [f for f in findings if f["severity"] != "ok"]

    counts, last = {}, None
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        cat = f.get("category", "")
        if cat != last:
            heading = SECTION.get(cat, cat.upper())
            if heading:
                print(f"\n{color(heading, 'bold', t)}")
            last = cat
        sev = f["severity"]
        tag = (color("  ok  ", "ok", t) if sev == "ok"
               else color(f" {sev[:4].upper():4} ", sev, t))
        host = f.get("host", "")
        print(f"  {tag} [{host}] {f['title']}: {f['detail']}")
        where = f.get("where") or f.get("evidence") or ""
        if verbose and where:
            print(f"          {color(where, 'dim', t)}")

    if not findings:
        print(color(f"  {empty}", "ok", t))
    tally = "  ".join(f"{k}={counts[k]}" for k in
                      ("critical", "high", "medium", "low") if k in counts)
    print(f"\n{len([f for f in findings if f['severity'] != 'ok'])} findings   "
          f"{tally or 'none'}")
    return counts


def cmd_hidden(args, store):
    print(f"Cross-view process scan on {'+'.join(_hosts(args))} — comparing "
          f"independent enumerations…\n")
    findings, _ = hidden.audit(hosts=_hosts(args), deep=args.deep)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    for f in findings:
        f.setdefault("category", "")
    counts = _report(findings, verbose=True, severity=args.severity,
                     sev_order=hidden.SEV_ORDER, show_ok=True,
                     empty="every view agrees — no processes hiding")
    if not any(k in counts for k in ("critical", "high")):
        print(color("  all process views agree.", "ok", _tty()))


def cmd_spy(args, store):
    print("Auditing for monitoring software, capability use and input control…\n")
    findings = spyware.sort_findings(spyware.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            empty="no monitoring software or capability abuse found")


def cmd_boot(args, store):
    print("Reconstructing what ran at startup…\n")
    findings = startup.sort_findings(startup.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=startup.SEV_ORDER, show_ok=True,
            empty="nothing notable at boot")


def cmd_firewall(args, store):
    print(f"Auditing firewall posture and inbound connections on "
          f"{'+'.join(_hosts(args))}…\n")
    findings = firewall.audit(hosts=_hosts(args))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=firewall.SEV_ORDER, show_ok=args.verbose,
            empty="no inbound exposure found")


def cmd_intrusion(args, store):
    print("Looking for intrusion artifacts — pasted commands, stealers, "
          "extensions…\n")
    findings = intrusion.sort_findings(intrusion.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=intrusion.SEV_ORDER, show_ok=True,
            empty="no intrusion artifacts found")


def cmd_asep(args, store):
    print("Auditing autostart extensibility points…\n")
    findings = asep.sort_findings(asep.audit())
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=asep.SEV_ORDER, show_ok=True,
            empty="no autostart abuse found")


def cmd_serve(args, store):
    from . import server
    store.close()  # the daemon opens its own handles per thread
    server.serve(db_path=args.db, port=args.port, hosts=_hosts(args))


def cmd_investigate(args, store):
    """Everything at once, for when you think something is actually wrong."""
    t = _tty()
    hosts = _hosts(args)
    sections = [
        ("HIDDEN PROCESSES", lambda: hidden.audit(hosts=hosts, deep=args.deep)[0]),
        ("STARTUP", startup.audit),
        ("SPYWARE & CAPABILITY USE", lambda: spyware.sort_findings(spyware.audit())),
        ("INTRUSION ARTIFACTS", lambda: intrusion.sort_findings(intrusion.audit())),
        ("AUTOSTART EXTENSIBILITY", lambda: asep.sort_findings(asep.audit())),
        ("FIREWALL & INBOUND", lambda: firewall.audit(hosts=hosts)),
        ("CONTROL SURFACES", lambda: control.audit(hosts=hosts)),
    ]
    worst = {}
    for title, fn in sections:
        print(f"\n{color('━' * 72, 'dim', t)}")
        print(color(title, "bold", t))
        print(color("━" * 72, "dim", t))
        try:
            findings = fn()
        except Exception as exc:  # one failing collector must not kill the report
            print(color(f"  section failed: {exc}", "medium", t))
            continue
        for f in findings:
            f.setdefault("category", "")
        counts = _report(findings, verbose=args.verbose,
                         severity=args.severity or "medium")
        for k, v in counts.items():
            worst[k] = worst.get(k, 0) + v

    print(f"\n{color('━' * 72, 'dim', t)}")
    tally = "  ".join(f"{k}={worst[k]}" for k in
                      ("critical", "high", "medium", "low") if k in worst)
    print(f"{color('TOTAL', 'bold', t)}   {tally or 'nothing at medium or above'}")


def cmd_procs(args, store):
    rows = store.list_procs(approved=args.approved, limit=args.limit)
    print(f"{'FP':<18}{'HOST':<6}{'APPR':<6}{'SEEN':<6}{'LAST':<21}NAME / CMD")
    for r in rows:
        print(f"{r['fp']:<18}{r['host']:<6}{'yes' if r['approved'] else 'no':<6}"
              f"{r['seen_count']:<6}{iso(r['last_seen']):<21}"
              f"{short(r['name'] + '  ' + (r['cmdline'] or ''), 60)}")
    print(f"\n{len(rows)} rows")


def cmd_peers(args, store):
    rows = store.list_peers(scope=args.scope, limit=args.limit)
    print(f"{'REMOTE':<44}{'SCOPE':<10}{'HOST':<6}{'SEEN':<6}{'LAST':<21}PROCESS")
    for r in rows:
        endpoint = f"{r['remote_ip']}:{r['remote_port']}"
        print(f"{endpoint:<44}{r['scope']:<10}{r['host']:<6}{r['seen_count']:<6}"
              f"{iso(r['last_seen']):<21}{short(r['pname'] or r['fp'], 30)}"
              f"{('  ' + r['rdns']) if r['rdns'] else ''}")
    print(f"\n{len(rows)} rows")


def cmd_events(args, store):
    since = now() - args.since * 3600 if args.since else None
    rows = store.list_events(limit=args.limit, severity=args.severity, since=since)
    t = _tty()
    for r in rows:
        tag = color(f" {r['severity'][:4].upper():4} ", r["severity"], t)
        print(f"{iso(r['ts'])} {tag} [{r['host']}/{r['pid']}] {r['name']} "
              f"— {detect.explain((r['reasons'] or '').split(',')) if r['reasons'] else r['kind']}")
        if args.verbose:
            print(f"    {short(r['cmdline'] or '', 110)}")
    print(f"\n{len(rows)} events")


def cmd_approve(args, store):
    n = 0
    for fp in args.fingerprint:
        n += store.set_approved(fp, 1, args.note)
    print(f"approved {n} fingerprint(s)")


def cmd_status(args, store):
    b = store.get_meta("baseline_at")
    total = len(store.known_fps())
    appr = len(store.list_procs(approved=1, limit=100000))
    ev = store.list_events(limit=1)
    print(f"database      {store.path}")
    print(f"baseline      {iso(int(b)) if b else 'not taken — run `sentry baseline`'}")
    print(f"fingerprints  {total} known, {appr} approved")
    print(f"peers         {len(store.list_peers(limit=100000))} recorded")
    print(f"last event    {iso(ev[0]['ts']) if ev else '—'}")
    print(f"windows side  "
          f"{'reachable' if collect_windows.available() else 'unavailable'}")


# ---------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(
        prog="sentry",
        description="Watch processes, scripts, network peers and control surfaces "
                    "across WSL and Windows.",
    )
    p.add_argument("--db", default=DEFAULT_DB, help="database path")
    p.add_argument("--host", choices=["wsl", "win", "all"], default="all")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="record the current state as known-good")
    b.add_argument("--reset", action="store_true",
                   help="forget the old baseline first instead of adding to it")
    b.set_defaults(fn=cmd_baseline)

    s = sub.add_parser("scan", help="one pass: report drift and suspicious traits")
    s.add_argument("--enrich", action="store_true", help="reverse-DNS public IPs")
    s.add_argument("--json", action="store_true")
    s.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(fn=cmd_scan)

    w = sub.add_parser("watch", help="scan continuously")
    w.add_argument("-i", "--interval", type=int, default=60)
    w.add_argument("--enrich", action="store_true")
    w.add_argument("-v", "--verbose", action="store_true", help="print quiet passes too")
    w.add_argument("--limit", type=int, default=10)
    w.set_defaults(fn=cmd_watch)

    c = sub.add_parser("control",
                       help="audit persistence, remote access and security controls")
    c.add_argument("--category", choices=["persistence", "remote", "defense"])
    c.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    c.add_argument("--json", action="store_true")
    c.add_argument("-v", "--verbose", action="store_true")
    c.set_defaults(fn=cmd_control)

    h = sub.add_parser("hidden",
                       help="cross-view scan for processes hiding from listings")
    h.add_argument("--deep", action="store_true",
                   help="sweep the full pid range instead of the first 65536")
    h.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    h.add_argument("--json", action="store_true")
    h.set_defaults(fn=cmd_hidden)

    sp = sub.add_parser("spy",
                        help="monitoring software, mic/camera use, input control")
    sp.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_spy)

    bo = sub.add_parser("boot",
                        help="what ran at startup, incl. windows that flash and close")
    bo.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    bo.add_argument("-v", "--verbose", action="store_true")
    bo.add_argument("--json", action="store_true")
    bo.set_defaults(fn=cmd_boot)

    fw = sub.add_parser("firewall",
                        help="firewall posture, inbound rules and remote connections")
    fw.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    fw.add_argument("-v", "--verbose", action="store_true")
    fw.add_argument("--json", action="store_true")
    fw.set_defaults(fn=cmd_firewall)

    it = sub.add_parser("intrusion",
                        help="pasted commands, infostealer and extension artifacts")
    it.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    it.add_argument("-v", "--verbose", action="store_true")
    it.add_argument("--json", action="store_true")
    it.set_defaults(fn=cmd_intrusion)

    ap = sub.add_parser("asep",
                        help="autostart extensibility points beyond Run keys")
    ap.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.set_defaults(fn=cmd_asep)

    sv = sub.add_parser("serve",
                        help="run the 24/7 daemon and local dashboard")
    sv.add_argument("-p", "--port", type=int, default=8787)
    sv.set_defaults(fn=cmd_serve)

    inv = sub.add_parser("investigate",
                         help="run every audit at once — start here if you suspect something")
    inv.add_argument("--deep", action="store_true")
    inv.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    inv.add_argument("-v", "--verbose", action="store_true")
    inv.set_defaults(fn=cmd_investigate)

    pr = sub.add_parser("procs", help="list fingerprints in the baseline")
    pr.add_argument("--approved", type=int, choices=[0, 1])
    pr.add_argument("--limit", type=int, default=60)
    pr.set_defaults(fn=cmd_procs)

    pe = sub.add_parser("peers", help="list observed network peers")
    pe.add_argument("--scope", choices=["public", "private", "loopback"])
    pe.add_argument("--limit", type=int, default=60)
    pe.set_defaults(fn=cmd_peers)

    e = sub.add_parser("events", help="recent alerts")
    e.add_argument("--limit", type=int, default=40)
    e.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    e.add_argument("--since", type=int, metavar="HOURS")
    e.add_argument("-v", "--verbose", action="store_true")
    e.set_defaults(fn=cmd_events)

    a = sub.add_parser("approve", help="mark fingerprints as known-good")
    a.add_argument("fingerprint", nargs="+")
    a.add_argument("--note", default="")
    a.set_defaults(fn=cmd_approve)

    st = sub.add_parser("status", help="show what sentry knows so far")
    st.set_defaults(fn=cmd_status)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    try:
        args.fn(args, store)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
