"""Report generation: executive PDF, technical PDF, CSV and JSON."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .. import __version__
from ..db import Database
from .pdf import build_executive, build_technical

REPORT_KINDS = {"executive": "pdf", "technical": "pdf", "csv": "csv", "json": "json"}

CSV_FIELDS = ["fingerprint", "severity", "risk_score", "status", "host", "port", "protocol", "service", "title", "category",
              "check_id", "cve", "base_score", "cvss_version", "cvss_vector", "epss", "epss_percentile", "kev", "exploit_available",
              "cwe", "owasp", "evidence", "impact", "recommendation", "first_seen_at", "last_seen_at"]


def export_csv(db: Database, scan_id: int, out: Path) -> Path:
    rows = db.scan_findings(scan_id)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return out


def export_json(db: Database, scan_id: int, out: Path) -> Path:
    scan = db.get_scan(scan_id)
    payload = {
        "generator": f"ENSAT {__version__}",
        "scan": {k: v for k, v in scan.items() if not k.endswith("_json")},
        "summary": db.severity_counts(scan_id),
        "hosts": db.scan_hosts(scan_id),
        "services": db.scan_services(scan_id),
        "findings": db.scan_findings(scan_id),
    }
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return out


def report_path(out_dir: Path, scan_id: int, kind: str) -> Path:
    ext = REPORT_KINDS[kind]
    name = {"executive": "executive", "technical": "technical", "csv": "findings", "json": "data"}[kind]
    return Path(out_dir) / f"ensat_scan_{scan_id}_{name}.{ext}"


def generate(db: Database, scan_id: int, kind: str, out_dir: Path) -> Path:
    if kind not in REPORT_KINDS:
        raise ValueError(f"Unknown report type '{kind}'. Choose from {', '.join(REPORT_KINDS)}")
    if not db.get_scan(scan_id):
        raise ValueError(f"Scan #{scan_id} not found")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out = report_path(out_dir, scan_id, kind)
    return {"executive": build_executive, "technical": build_technical, "csv": export_csv, "json": export_json}[kind](db, scan_id, out)
