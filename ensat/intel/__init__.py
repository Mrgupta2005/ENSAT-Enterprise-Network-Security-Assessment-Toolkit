"""Vulnerability intelligence: CPE -> NVD CVEs, enriched with EPSS and CISA KEV."""
from __future__ import annotations

import logging
from typing import Callable, Optional

import requests

from ..config import Settings
from ..models import Finding, Host
from .cache import IntelCache
from .cpe import parse_cpe
from .feeds import EpssClient, KevCatalog
from .nvd import CveRecord, IntelUnavailable, NvdClient, parse_cve

log = logging.getLogger("ensat.intel")

__all__ = ["ThreatIntel", "CveRecord", "IntelUnavailable", "parse_cve"]


class ThreatIntel:
    def __init__(self, cfg: Settings, session: requests.Session | None = None, offline: bool | None = None):
        offline = cfg.offline if offline is None else offline
        self.cache = IntelCache(cfg.data_dir / "intel_cache.db")
        self.nvd = NvdClient(cfg.nvd_url, cfg.nvd_api_key, self.cache, cfg.nvd_cache_days, cfg.http_timeout, session, offline)
        self.epss = EpssClient(cfg.epss_url, self.cache, cfg.http_timeout, session, offline)
        self.kev = KevCatalog(cfg.kev_url, cfg.kev_cache_path, cfg.kev_cache_hours, 60, session, offline)
        self.max_cves = cfg.max_cves_per_service
        self.warnings: list[str] = []

    def _warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)
            log.warning(msg)

    def cve_findings(self, hosts: list[Host], progress: Optional[Callable[[str, float], None]] = None) -> list[Finding]:
        work = []
        for host in hosts:
            for svc in host.open_services:
                for raw in svc.cpes:
                    cpe = parse_cpe(raw)
                    if cpe and cpe.has_version and cpe.part in ("a", "h"):
                        work.append((host, svc, cpe, raw))
        findings: list[Finding] = []
        nvd_down = False
        for i, (host, svc, cpe, raw) in enumerate(work):
            if progress:
                progress(f"NVD lookup: {cpe.vendor} {cpe.product} {cpe.version} ({i + 1}/{len(work)})", i / max(len(work), 1))
            if nvd_down:
                break
            try:
                records = self.nvd.cves_for_cpe(cpe, self.max_cves)
            except IntelUnavailable as exc:
                self._warn(f"CVE lookup skipped: {exc}")
                nvd_down = True
                continue
            for rec in records:
                findings.append(self._to_finding(host, svc, cpe, raw, rec))
        self.enrich(findings)
        return findings

    def _to_finding(self, host, svc, cpe, raw_cpe, rec: CveRecord) -> Finding:
        label = svc.label
        return Finding(
            host=host.address, port=svc.port, protocol=svc.protocol, check_id="CVE", category="vulnerability",
            title=f"{rec.id}: {label}", base_score=rec.base_score, service=svc.service, cve=rec.id,
            evidence=f"Detected {label} ({raw_cpe}); NVD lists this version as affected.",
            impact=rec.description[:1500],
            recommendation=f"Upgrade or patch {label} to a release not affected by {rec.id}; follow the vendor advisory. "
                           "If patching is delayed, restrict network access to the service.",
            cvss_version=rec.score_source, cvss_vector=rec.vector, cvss3=rec.cvss3, cvss4=rec.cvss4,
            cwe=", ".join(rec.cwes), exploit_available=bool(rec.exploit_refs), owasp="A06:2021 Vulnerable and Outdated Components",
            references=(rec.exploit_refs + [r for r in rec.references if r not in rec.exploit_refs])[:8],
        )

    def enrich(self, findings: list[Finding]) -> None:
        """Attach EPSS and KEV data to every CVE finding in place."""
        cves = [f.cve for f in findings if f.cve]
        if not cves:
            return
        try:
            scores = self.epss.scores(cves)
        except IntelUnavailable as exc:
            self._warn(str(exc))
            scores = {}
        for f in findings:
            if not f.cve:
                continue
            if f.cve.upper() in scores:
                f.epss, f.epss_percentile = scores[f.cve.upper()]
            entry = self.kev.get(f.cve)
            if entry:
                f.kev = True
                f.exploit_available = True
                action = entry.get("requiredAction", "")
                if action:
                    f.recommendation = f"CISA KEV required action: {action} " + f.recommendation
        if len(self.kev) == 0:
            self._warn("CISA KEV catalog not available yet; KEV status could not be checked.")

    def lookup(self, cve_id: str) -> Optional[dict]:
        rec = self.nvd.get_cve(cve_id)
        if not rec:
            return None
        epss = {}
        try:
            epss = self.epss.scores([rec.id])
        except IntelUnavailable as exc:
            self._warn(str(exc))
        kev = self.kev.get(rec.id)
        return {"record": rec, "epss": epss.get(rec.id), "kev": kev}
