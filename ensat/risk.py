"""Contextual risk engine.

The base score is CVSS (for CVEs) or the check's rule score. It is then
adjusted for threat likelihood (CISA KEV, EPSS, public exploits) and for
business context (internet exposure, asset criticality, business impact).
Every adjustment is recorded in ``risk_factors`` so the result is explainable.

    CVSS 9.8 + KEV + EPSS 92% + internet-facing + critical asset -> 10.0 Critical
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import SEVERITY_RANK, Finding, severity_for

SEVERITY_WEIGHT = {"Critical": 10.0, "High": 5.0, "Medium": 2.0, "Low": 0.5, "Info": 0.0}
CRITICALITY_ADJ = {"critical": 1.0, "high": 0.5, "medium": 0.0, "low": -1.0}
IMPACT_ADJ = {"high": 0.5, "medium": 0.0, "low": -0.5}


@dataclass
class AssetContext:
    criticality: str = "medium"        # critical | high | medium | low
    business_impact: str = "medium"    # high | medium | low
    internet_exposed: bool = False


def is_internet_facing(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def score_finding(f: Finding, ctx: AssetContext) -> Finding:
    base = max(0.0, min(10.0, float(f.base_score or 0.0)))
    factors = [f"Base {base:.1f} ({f.cvss_version or 'ENSAT rule'})"]
    if base == 0.0:
        f.risk_score, f.severity, f.risk_factors = 0.0, "Info", factors + ["Informational finding"]
        return f
    score = base
    if f.kev:
        score += 1.5
        factors.append("+1.5 listed in CISA KEV (exploited in the wild)")
    elif f.exploit_available:
        score += 0.5
        factors.append("+0.5 public exploit referenced")
    if f.epss is not None:
        if f.epss >= 0.5:
            score += 1.0
            factors.append(f"+1.0 EPSS {f.epss:.0%} (high exploitation probability)")
        elif f.epss >= 0.1:
            score += 0.5
            factors.append(f"+0.5 EPSS {f.epss:.0%}")
        elif f.epss < 0.01 and not f.kev:
            score -= 0.5
            factors.append(f"-0.5 EPSS {f.epss:.2%} (low exploitation probability)")
    if ctx.internet_exposed:
        score += 1.0
        factors.append("+1.0 internet-exposed asset")
    adj = CRITICALITY_ADJ.get(ctx.criticality, 0.0)
    if adj:
        factors.append(f"{adj:+.1f} asset criticality: {ctx.criticality}")
        score += adj
    adj = IMPACT_ADJ.get(ctx.business_impact, 0.0)
    if adj:
        factors.append(f"{adj:+.1f} business impact: {ctx.business_impact}")
        score += adj
    if f.kev:
        floor = 9.0 if base >= 7.0 else 7.0
        if score < floor:
            factors.append(f"KEV floor applied ({floor:.1f})")
            score = floor
    score = round(max(0.1, min(10.0, score)), 1)
    f.risk_score, f.severity, f.risk_factors = score, severity_for(score), factors
    return f


def assess(findings: list[Finding], contexts: dict[str, AssetContext]) -> list[Finding]:
    """Score every finding with its asset's context and return them in priority order."""
    for f in findings:
        score_finding(f, contexts.get(f.host) or AssetContext(internet_exposed=is_internet_facing(f.host)))
    return prioritise(findings)


def prioritise(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -f.risk_score, not f.kev, -(f.epss or 0), f.host, f.port or 0))


def risk_index(severity_counts: dict[str, int]) -> float:
    """Single weighted number used to compare scans (Critical=10, High=5, Medium=2, Low=0.5)."""
    return sum(SEVERITY_WEIGHT.get(s, 0) * n for s, n in severity_counts.items())


def asset_risk(scores: list[float]) -> float:
    if not scores:
        return 0.0
    top = max(scores)
    extra = 0.1 * sum(1 for s in scores if s >= 7.0)
    return round(min(10.0, top + extra), 1)
