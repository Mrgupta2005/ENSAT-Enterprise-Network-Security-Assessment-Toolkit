"""ENSAT command-line interface."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .config import settings, setup_logging
from .db import Database
from .models import SEVERITIES, STATUSES, ScanOptions
from .validation import AuthorizationError, ValidationError

console = Console()
SEV_STYLE = {"Critical": "bold white on red", "High": "bold red", "Medium": "yellow", "Low": "cyan", "Info": "dim"}


def _db() -> Database:
    return Database(settings.db_path)


def _sev(s: str) -> str:
    return f"[{SEV_STYLE.get(s, '')}]{s}[/]"


def _resolve_scan(db: Database, scan_id: int | None) -> dict | None:
    scan = db.get_scan(scan_id) if scan_id else db.latest_scan()
    if not scan:
        console.print("[yellow]No completed scans found.[/] Run: python -m ensat assess <authorized-target>")
    return scan


# ------------------------------------------------------------ commands ----

def cmd_assess(args) -> int:
    from .pipeline import AssessmentError, assess

    authorized_by = ""
    if args.authorized:
        authorized_by = args.operator or settings.operator
    opts = ScanOptions(
        target=" ".join(args.target), profile=args.profile, ports=args.ports, service_detection=not args.no_service_detection,
        os_detection=args.os, udp=args.udp, skip_discovery=True if args.no_ping else None, nse_scripts=not args.no_scripts,
        tls_checks=not args.no_tls, web_checks=not args.no_web, cve_lookup=not args.no_cve, timeout=args.timeout,
        authorized_by=authorized_by, authorization_note=args.note or "",
    )
    reports = ("executive", "technical") if args.report == "both" else (() if args.report == "none" else (args.report,))
    console.print(Panel.fit(f"[bold cyan]ENSAT {__version__}[/] authorized assessment of [bold]{opts.target}[/] "
                            f"(profile: {opts.profile})", border_style="cyan"))
    try:
        with Progress(TextColumn("{task.description}"), BarColumn(), TextColumn("{task.percentage:>3.0f}%"), TimeElapsedColumn(),
                      console=console, transient=True) as prog:
            task = prog.add_task("Starting", total=1.0)
            result = assess(opts, settings, _db(), progress=lambda msg, frac: prog.update(task, description=msg[:70], completed=frac),
                            report_types=reports)
    except (ValidationError, AuthorizationError) as exc:
        console.print(f"[red]Not started:[/] {exc}")
        return 2
    except AssessmentError as exc:
        console.print(f"[red]Scan #{exc.scan_id} failed:[/] {exc}")
        return 2

    for w in result.warnings:
        console.print(f"[yellow]![/] {w}")
    up = [h for h in result.hosts if h.status == "up"]
    console.print(f"Scan #{result.scan_id} completed in {result.duration:.1f}s: {len(up)} live host(s), "
                  f"{sum(len(h.open_services) for h in up)} open service(s), {len(result.findings)} finding(s)")
    t = result.transitions
    if t.get("reopened") or t.get("verified"):
        console.print(f"Remediation tracking: {t.get('verified', 0)} verified fixed, {t.get('reopened', 0)} reopened")
    _print_findings([f.to_dict() | {"status": "", "fingerprint": f.fingerprint} for f in result.findings], limit=args.limit)
    counts = result.counts
    console.print("  ".join(f"{_sev(s)}: {counts.get(s, 0)}" for s in SEVERITIES))
    for kind, path in result.reports.items():
        console.print(f"[green]{kind.title()} report:[/] {path}")
    return 0


def _print_findings(rows: list[dict], limit: int = 50, show_status: bool = False) -> None:
    if not rows:
        console.print("[green]No findings.[/]")
        return
    t = Table("ID", "Severity", "Risk", "Asset", "Service", "Finding", *(["Status"] if show_status else []), "KEV", "EPSS", header_style="bold")
    for r in rows[:limit]:
        epss = f"{r['epss']:.0%}" if r.get("epss") is not None else ""
        t.add_row(r["fingerprint"][:8], _sev(r["severity"]), f"{r['risk_score']:.1f}", f"{r['host']}:{r['port'] or '-'}",
                  r.get("service") or "", r["title"][:70], *([r.get("status", "")] if show_status else []),
                  "[bold red]YES[/]" if r.get("kev") else "", epss)
    console.print(t)
    if len(rows) > limit:
        console.print(f"... {len(rows) - limit} more (use --limit)")


def cmd_history(args) -> int:
    scans = _db().list_scans(args.limit)
    if not scans:
        console.print("No scans yet.")
        return 0
    t = Table("Scan", "Started (UTC)", "Target", "Profile", "Status", "Hosts", "Services", "Crit", "High", "Med", "Low", header_style="bold")
    for s in scans:
        t.add_row(str(s["id"]), s["started_at"][:19].replace("T", " "), s["target"], s["profile"] or "",
                  s["status"], str(s["hosts_up"] or 0), str(s["services"]), str(s["critical"]), str(s["high"]), str(s["medium"]), str(s["low"]))
    console.print(t)
    return 0


def cmd_findings(args) -> int:
    db = _db()
    if args.scan_id:
        rows = db.scan_findings(args.scan_id)
    else:
        rows = db.current_findings(include_closed=args.all)
    if args.severity:
        rows = [r for r in rows if r["severity"].lower() == args.severity.lower()]
    if args.status:
        rows = [r for r in rows if r["status"] == args.status.upper()]
    if args.kev:
        rows = [r for r in rows if r["kev"]]
    _print_findings(rows, args.limit, show_status=True)
    return 0


def cmd_status(args) -> int:
    db = _db()
    fps = []
    for ref in args.ids:
        fp = db.resolve_fingerprint(ref)
        if not fp:
            console.print(f"[red]Unknown or ambiguous finding ID:[/] {ref}")
            return 1
        fps.append(fp)
    n = db.update_status(fps, args.new_status, args.operator or settings.operator, args.note or "")
    console.print(f"Updated {n} finding(s) to {args.new_status.upper()}")
    return 0


def cmd_compare(args) -> int:
    from .compare import compare_scans
    db = _db()
    after = db.get_scan(args.after) if args.after else db.latest_scan()
    if not after:
        console.print("No scans to compare.")
        return 1
    before = db.get_scan(args.before) if args.before else db.previous_scan(after["id"])
    if not before:
        console.print(f"No earlier scan of {after['target']} to compare with. Run another assessment first.")
        return 1
    c = compare_scans(db, before["id"], after["id"])
    t = Table("Severity", f"Before (#{before['id']})", f"After (#{after['id']})", "Change", header_style="bold")
    for s in SEVERITIES[:4]:
        d = c.delta(s)
        t.add_row(_sev(s), str(c.before_counts[s]), str(c.after_counts[s]), f"[green]{d:+d}[/]" if d < 0 else f"[red]{d:+d}[/]" if d > 0 else "0")
    console.print(t)
    colour = "green" if c.risk_reduction_pct > 0 else "red" if c.risk_reduction_pct < 0 else "white"
    console.print(f"[bold {colour}]{c.headline}[/] (risk index {c.before_index:.0f} -> {c.after_index:.0f})")
    console.print(f"Resolved: {len(c.resolved_findings)}   New: {len(c.new_findings)}   Persisting: {len(c.persisting_findings)}")
    for label, items in (("New assets", c.new_assets), ("Missing assets", c.missing_assets),
                         ("New services", c.new_services), ("Closed services", c.closed_services)):
        if items:
            console.print(f"{label}: {', '.join(items[:15])}")
    return 0


def cmd_report(args) -> int:
    from .reporting import REPORT_KINDS, generate
    db = _db()
    scan = _resolve_scan(db, args.scan_id)
    if not scan:
        return 1
    kinds = list(REPORT_KINDS) if args.type == "all" else [args.type]
    for kind in kinds:
        try:
            path = generate(db, scan["id"], kind, Path(args.output) if args.output else settings.report_dir)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]{kind} report failed:[/] {exc}")
            return 2
        console.print(f"[green]{kind.title()}:[/] {path}")
    return 0


def cmd_assets(args) -> int:
    db = _db()
    if args.address:
        fields = {k: v for k, v in {"criticality": args.criticality, "business_impact": args.impact, "exposure": args.exposure,
                                    "owner": args.owner, "tags": args.tags, "notes": args.notes}.items() if v is not None}
        if args.known is not None:
            fields["known"] = int(args.known)
        if not fields:
            console.print("Nothing to update. Use --criticality/--impact/--exposure/--owner/--tags/--notes/--known.")
            return 1
        db.update_asset(args.address, **fields)
        n = db.rescore_open()
        console.print(f"Updated asset {args.address}; re-scored {n} open finding(s).")
        return 0
    rows = db.assets()
    if not rows:
        console.print("No assets yet.")
        return 0
    t = Table("Address", "Hostname", "OS", "MAC / Vendor", "Criticality", "Internet", "Known", "Risk", "Open findings", "Last seen", header_style="bold")
    for a in rows:
        t.add_row(a["address"], a["hostname"] or "", (a["os_name"] or "")[:30], " ".join(x for x in (a["mac"], a["vendor"]) if x),
                  a["criticality"], "yes" if a["internet_exposed"] else "no", "yes" if a["known"] else "[yellow]no[/]",
                  f"{a['risk_score']:.1f}", str(a["open_findings"]), (a["last_seen"] or "")[:10])
    console.print(t)
    return 0


def cmd_cve(args) -> int:
    from .intel import IntelUnavailable, ThreatIntel
    intel = ThreatIntel(settings)
    try:
        if args.query.upper().startswith("CVE-"):
            res = intel.lookup(args.query)
            if not res:
                console.print("Not found.")
                return 1
            r = res["record"]
            console.print(Panel(f"[bold]{r.id}[/]  {r.score_source} {r.base_score}  {r.vector}\n"
                                f"EPSS: {res['epss'][0]:.2%}" if res["epss"] else f"[bold]{r.id}[/]  {r.score_source} {r.base_score}  {r.vector}"))
            console.print(f"KEV: {'[bold red]YES[/] - ' + res['kev'].get('requiredAction', '') if res['kev'] else 'no'}")
            console.print(f"CWE: {', '.join(r.cwes) or 'n/a'}   Published: {r.published}")
            console.print(r.description)
        else:
            recs = intel.nvd.search(args.query, args.limit)
            t = Table("CVE", "Score", "Published", "Description", header_style="bold")
            for r in recs:
                t.add_row(r.id, f"{r.base_score:.1f}", r.published, r.description[:90])
            console.print(t)
    except IntelUnavailable as exc:
        console.print(f"[red]{exc}[/]")
        return 2
    return 0


def cmd_intel(args) -> int:
    from .intel import IntelUnavailable, ThreatIntel
    intel = ThreatIntel(settings)
    try:
        n = intel.kev.refresh()
        console.print(f"[green]CISA KEV catalog updated:[/] {n} known exploited vulnerabilities")
    except IntelUnavailable as exc:
        console.print(f"[red]{exc}[/]")
        return 2
    return 0


def cmd_dashboard(args) -> int:
    app = Path(__file__).resolve().parent / "dashboard" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(app), "--server.port", str(args.port), "--browser.gatherUsageStats", "false"]
    if args.headless:
        cmd += ["--server.headless", "true"]
    console.print(f"Starting dashboard on http://localhost:{args.port}  (Ctrl+C to stop)")
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0


# --------------------------------------------------------------- parser ----

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ensat", description="ENSAT - Enterprise Network Security Assessment Toolkit (authorized use only)")
    p.add_argument("--version", action="version", version=f"ENSAT {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="Log to the console as well as logs/ensat.log")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("assess", "scan"):
        a = sub.add_parser(name, help="Run the full assessment pipeline (scan, checks, CVEs, risk, report)" if name == "assess" else "Alias for assess")
        a.add_argument("target", nargs="+", help="Authorized host(s), range(s) or subnet(s), e.g. 192.168.1.10 10.0.0.0/24")
        a.add_argument("--profile", choices=["quick", "standard", "full"], default="standard")
        a.add_argument("--ports", help="Ports, e.g. 22,80,443 or 1-1024 (overrides the profile)")
        a.add_argument("--os", action="store_true", help="OS detection (needs root/Administrator)")
        a.add_argument("--udp", action="store_true", help="Scan common UDP services (needs root/Administrator)")
        a.add_argument("--no-ping", action="store_true", help="Treat all targets as up (skip host discovery)")
        a.add_argument("--no-service-detection", action="store_true")
        a.add_argument("--service-detection", action="store_true", help=argparse.SUPPRESS)  # V1 compatibility
        a.add_argument("--no-scripts", action="store_true", help="Disable safe NSE scripts")
        a.add_argument("--no-tls", action="store_true", help="Skip TLS certificate/protocol checks")
        a.add_argument("--no-web", action="store_true", help="Skip passive web checks")
        a.add_argument("--no-cve", action="store_true", help="Skip NVD/EPSS/KEV lookups")
        a.add_argument("--authorized", action="store_true", help="Confirm written authorization for targets outside scope.txt")
        a.add_argument("--operator", help="Name recorded as the authorizing operator")
        a.add_argument("--note", help="Authorization reference, e.g. ticket or engagement ID")
        a.add_argument("--report", choices=["executive", "technical", "both", "none"], default="both")
        a.add_argument("--timeout", type=int, default=settings.scan_timeout, help="Nmap timeout in seconds")
        a.add_argument("--limit", type=int, default=40, help="Max findings to print")
        a.set_defaults(func=cmd_assess)

    h = sub.add_parser("history", help="List previous scans")
    h.add_argument("--limit", type=int, default=30)
    h.set_defaults(func=cmd_history)

    f = sub.add_parser("findings", help="List findings (current issues by default)")
    f.add_argument("--scan-id", type=int)
    f.add_argument("--severity", choices=[s.lower() for s in SEVERITIES] + SEVERITIES)
    f.add_argument("--status", choices=STATUSES + [s.lower() for s in STATUSES])
    f.add_argument("--kev", action="store_true", help="Only CISA KEV findings")
    f.add_argument("--all", action="store_true", help="Include closed findings")
    f.add_argument("--limit", type=int, default=100)
    f.set_defaults(func=cmd_findings)

    s = sub.add_parser("status", help="Update remediation status, e.g. ensat status IN_PROGRESS 3f2a9c1b")
    s.add_argument("new_status", type=str.upper, choices=STATUSES)
    s.add_argument("ids", nargs="+", help="Finding ID(s) as shown in 'ensat findings'")
    s.add_argument("--note")
    s.add_argument("--operator")
    s.set_defaults(func=cmd_status)

    c = sub.add_parser("compare", help="Compare two scans (default: latest vs previous of the same target)")
    c.add_argument("--before", type=int)
    c.add_argument("--after", type=int)
    c.set_defaults(func=cmd_compare)

    for name, default in (("report", "all"), ("export", "json")):
        r = sub.add_parser(name, help="Generate reports for a scan" if name == "report" else "Export scan data")
        r.add_argument("--scan-id", type=int, help="Scan to report on (default: latest)")
        r.add_argument("--latest", action="store_true", help="Use the latest scan (default)")
        r.add_argument("--type", "--format", dest="type", choices=["executive", "technical", "csv", "json", "all", "pdf"], default=default)
        r.add_argument("--output", help="Output directory (default: reports/)")
        r.set_defaults(func=lambda a: cmd_report(argparse.Namespace(**{**vars(a), "type": "technical" if a.type == "pdf" else a.type})))

    a = sub.add_parser("assets", help="List assets, or update one: ensat assets 10.0.0.5 --criticality critical")
    a.add_argument("address", nargs="?")
    a.add_argument("--criticality", choices=["critical", "high", "medium", "low"])
    a.add_argument("--impact", choices=["high", "medium", "low"], help="Business impact")
    a.add_argument("--exposure", choices=["auto", "internet", "internal"])
    a.add_argument("--owner")
    a.add_argument("--tags")
    a.add_argument("--notes")
    a.add_argument("--known", type=lambda v: v.lower() in ("1", "yes", "true"), help="yes/no")
    a.set_defaults(func=cmd_assets)

    v = sub.add_parser("cve", help="Look up a CVE ID or search NVD by keyword")
    v.add_argument("query")
    v.add_argument("--limit", type=int, default=20)
    v.set_defaults(func=cmd_cve)

    i = sub.add_parser("intel-update", help="Refresh the CISA KEV catalog cache")
    i.set_defaults(func=cmd_intel)

    d = sub.add_parser("dashboard", help="Launch the Streamlit dashboard")
    d.add_argument("--port", type=int, default=8501)
    d.add_argument("--headless", action="store_true")
    d.set_defaults(func=cmd_dashboard)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        code = args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
