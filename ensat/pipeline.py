"""One-command assessment pipeline: scan -> analyse -> CVE lookup -> risk -> store -> report."""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import checks
from .config import Settings
from .config import settings as default_settings
from .db import Database
from .models import Finding, Host, ScanOptions
from .parser import ParseError, parse_scan
from .risk import AssetContext
from .risk import assess as score_findings
from .scanner import NmapError, ScanRun, run_scan
from .validation import check_authorization, load_scope, parse_targets, validate_ports

log = logging.getLogger("ensat.pipeline")

ProgressFn = Callable[[str, float], None]


class AssessmentError(RuntimeError):
    def __init__(self, message: str, scan_id: int | None = None):
        super().__init__(message)
        self.scan_id = scan_id


@dataclass
class AssessmentResult:
    scan_id: int
    hosts: list[Host]
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    duration: float = 0.0
    transitions: dict = field(default_factory=dict)
    reports: dict[str, Path] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def _stage(progress: Optional[ProgressFn], lo: float, hi: float) -> ProgressFn:
    def inner(msg: str, frac: float) -> None:
        if progress:
            progress(msg, lo + (hi - lo) * max(0.0, min(1.0, frac)))
    return inner


def run_service_checks(hosts: list[Host], tls: bool, web: bool, progress: Optional[ProgressFn] = None):
    findings: list[Finding] = []
    tls_info: dict[str, dict] = {}
    web_info: dict[str, dict] = {}
    for h in hosts:
        if h.status == "up":
            findings += checks.check_exposure(h)
            findings += checks.check_scripts(h)
    jobs = []
    for h in hosts:
        if h.status != "up":
            continue
        for s in h.open_services:
            if s.protocol != "tcp":
                continue
            if tls and s.is_tls:
                jobs.append(("tls", h, s))
            if web and s.is_http:
                jobs.append(("web", h, s))
    if not jobs:
        return findings, tls_info, web_info

    def work(job):
        kind, h, s = job
        if kind == "tls":
            return job, checks.check_tls(h, s)
        return job, checks.check_web(h, s)

    done = 0
    with ThreadPoolExecutor(max_workers=12) as pool:
        for (kind, h, s), (fs, info) in pool.map(work, jobs):
            done += 1
            findings += fs
            key = f"{h.address}:{s.port}/{s.protocol}"
            if info:
                (tls_info if kind == "tls" else web_info)[key] = info
            if kind == "web" and info and info.get("technologies"):
                # versions disclosed in headers (e.g. "PHP/7.2.1") become CPEs for the CVE lookup
                for cpe in checks.web.cpes_from_technologies(info["technologies"]):
                    if cpe not in s.cpes:
                        s.cpes.append(cpe)
            if progress:
                progress(f"{kind.upper()} checks: {h.address}:{s.port}", done / len(jobs))
    return findings, tls_info, web_info


def inventory_findings(hosts: list[Host], assets: dict[str, dict], first_scan: bool) -> list[Finding]:
    out = []
    if first_scan:
        return out  # everything is "new" on the very first scan; don't flood the report
    for h in hosts:
        a = assets.get(h.address)
        if a and a["is_new"] and not a.get("known"):
            out.append(Finding(host=h.address, port=None, protocol="", check_id="INV-NEW-ASSET",
                               title="New, unrecognised asset discovered", category="inventory", base_score=3.0,
                               evidence=f"{h.address} {h.hostname or ''} {h.vendor or ''} first seen in this scan".strip(),
                               impact="Unmanaged devices are often unpatched and outside monitoring (shadow IT).",
                               recommendation="Identify the owner, add the asset to the inventory (mark it known) or remove it from the network."))
    return out


def assess(opts: ScanOptions, cfg: Settings | None = None, db: Database | None = None, intel=None,
           progress: Optional[ProgressFn] = None, scanner: Callable[..., ScanRun] = run_scan,
           report_types: tuple[str, ...] = ()) -> AssessmentResult:
    cfg = cfg or default_settings
    db = db or Database(cfg.db_path)
    started = time.perf_counter()

    # 1. validate + authorize (raises ValidationError / AuthorizationError before anything is stored)
    targets = parse_targets(opts.target, cfg.max_hosts)
    opts.ports = validate_ports(opts.ports)
    outside = check_authorization(targets, load_scope(cfg.scope_file), acknowledged=bool(opts.authorized_by))
    first_scan = db.latest_scan() is None
    scan_id = db.create_scan(opts, cfg.operator, out_of_scope=bool(outside))
    log.info("Scan #%s started: %s (profile=%s)", scan_id, opts.target, opts.profile)

    try:
        # 2. scan
        if progress:
            progress("Starting Nmap", 0.02)
        run = scanner(opts, _stage(progress, 0.02, 0.6))
        hosts = parse_scan(run.xml_documents)
        warnings = list(run.warnings)
        up = [h for h in hosts if h.status == "up"]
        if progress:
            progress(f"Discovered {len(up)} live host(s), {sum(len(h.open_services) for h in up)} open service(s)", 0.6)

        # 3. inventory
        assets = db.upsert_assets(scan_id, hosts)

        # 4. security checks
        findings, tls_info, web_info = run_service_checks(hosts, opts.tls_checks, opts.web_checks, _stage(progress, 0.6, 0.75))
        findings += inventory_findings(hosts, assets, first_scan)

        # 5. vulnerability intelligence
        if opts.cve_lookup:
            if intel is None:
                from .intel import ThreatIntel
                intel = ThreatIntel(cfg)
            findings += intel.cve_findings(hosts, _stage(progress, 0.75, 0.92))
            warnings += intel.warnings

        # 6. risk
        if progress:
            progress("Calculating risk", 0.93)
        contexts: dict[str, AssetContext] = {addr: db.context_for(a) for addr, a in assets.items()}
        findings = score_findings(findings, contexts)

        # 7. store
        duration = time.perf_counter() - started
        transitions = db.complete_scan(scan_id, hosts, findings, assets, duration=duration,
                                       nmap_args=" | ".join(run.commands), nmap_version=run.nmap_version,
                                       privileged=run.privileged, warnings=warnings, tls_info=tls_info, web_info=web_info)
    except (NmapError, ParseError) as exc:
        db.fail_scan(scan_id, str(exc), time.perf_counter() - started)
        raise AssessmentError(str(exc), scan_id) from exc
    except Exception as exc:
        log.exception("Scan #%s failed", scan_id)
        db.fail_scan(scan_id, f"{type(exc).__name__}: {exc}", time.perf_counter() - started)
        raise AssessmentError(f"Unexpected error: {exc}", scan_id) from exc

    result = AssessmentResult(scan_id, hosts, findings, warnings, duration, transitions)

    # 8. reports (failures here never lose the stored scan)
    if report_types:
        from .reporting import generate
        if progress:
            progress("Generating reports", 0.97)
        for kind in report_types:
            try:
                result.reports[kind] = generate(db, scan_id, kind, cfg.report_dir)
            except Exception as exc:  # noqa: BLE001
                log.exception("Report %s failed", kind)
                result.warnings.append(f"{kind} report failed: {exc}")
    if progress:
        progress("Assessment complete", 1.0)
    log.info("Scan #%s completed in %.1fs: %s findings", scan_id, duration, len(findings))
    return result
