"""Before/after comparison of two scans."""
from __future__ import annotations

from dataclasses import dataclass, field

from .db import Database
from .models import SEVERITIES
from .risk import risk_index


@dataclass
class Comparison:
    before: dict
    after: dict
    before_counts: dict[str, int]
    after_counts: dict[str, int]
    before_index: float
    after_index: float
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    persisting_findings: list[dict] = field(default_factory=list)
    new_assets: list[str] = field(default_factory=list)
    missing_assets: list[str] = field(default_factory=list)
    new_services: list[str] = field(default_factory=list)
    closed_services: list[str] = field(default_factory=list)

    @property
    def risk_reduction_pct(self) -> float:
        if self.before_index == 0:
            return 0.0 if self.after_index == 0 else -100.0
        return round((self.before_index - self.after_index) / self.before_index * 100, 1)

    @property
    def headline(self) -> str:
        pct = self.risk_reduction_pct
        if pct > 0:
            return f"Risk reduced by {pct:.0f}%"
        if pct < 0:
            return f"Risk increased by {abs(pct):.0f}%"
        return "No change in overall risk"

    def delta(self, severity: str) -> int:
        return self.after_counts.get(severity, 0) - self.before_counts.get(severity, 0)


def compare_scans(db: Database, before_id: int, after_id: int) -> Comparison:
    before, after = db.get_scan(before_id), db.get_scan(after_id)
    if not before or not after:
        raise ValueError("Both scans must exist")
    bc, ac = db.severity_counts(before_id), db.severity_counts(after_id)
    bf = {f["fingerprint"]: f for f in db.scan_findings(before_id)}
    af = {f["fingerprint"]: f for f in db.scan_findings(after_id)}
    bh = {h["address"] for h in db.scan_hosts(before_id) if h["status"] == "up"}
    ah = {h["address"] for h in db.scan_hosts(after_id) if h["status"] == "up"}
    bs = {f'{s["address"]}:{s["port"]}/{s["protocol"]} {s["service"]}' for s in db.scan_services(before_id)}
    as_ = {f'{s["address"]}:{s["port"]}/{s["protocol"]} {s["service"]}' for s in db.scan_services(after_id)}
    order = {s: i for i, s in enumerate(SEVERITIES)}

    def ranked(items):
        return sorted(items, key=lambda f: (order.get(f["severity"], 9), -f["risk_score"]))

    return Comparison(
        before=before, after=after, before_counts=bc, after_counts=ac,
        before_index=risk_index(bc), after_index=risk_index(ac),
        new_findings=ranked([f for k, f in af.items() if k not in bf]),
        resolved_findings=ranked([f for k, f in bf.items() if k not in af]),
        persisting_findings=ranked([f for k, f in af.items() if k in bf]),
        new_assets=sorted(ah - bh), missing_assets=sorted(bh - ah),
        new_services=sorted(as_ - bs), closed_services=sorted(bs - as_),
    )
