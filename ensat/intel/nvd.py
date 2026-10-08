"""NVD CVE API 2.0 client with caching, rate limiting and local version verification."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import requests

from .cache import IntelCache
from .cpe import Cpe, candidates, cve_affects

log = logging.getLogger("ensat.nvd")


class IntelUnavailable(RuntimeError):
    """The external service could not be reached; callers should degrade gracefully."""


@dataclass
class CveRecord:
    id: str
    description: str = ""
    published: str = ""
    cvss3: float | None = None
    cvss3_vector: str = ""
    cvss3_version: str = ""
    cvss4: float | None = None
    cvss4_vector: str = ""
    cvss2: float | None = None
    severity: str = ""
    cwes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploit_refs: list[str] = field(default_factory=list)

    @property
    def base_score(self) -> float:
        for s in (self.cvss4, self.cvss3, self.cvss2):
            if s is not None:
                return float(s)
        return 5.0  # unscored (awaiting NVD analysis): treat as medium until scored

    @property
    def score_source(self) -> str:
        if self.cvss4 is not None:
            return "CVSS 4.0"
        if self.cvss3 is not None:
            return f"CVSS {self.cvss3_version or '3.x'}"
        if self.cvss2 is not None:
            return "CVSS 2.0"
        return "unscored"

    @property
    def vector(self) -> str:
        return self.cvss4_vector if self.cvss4 is not None else self.cvss3_vector


def parse_cve(item: dict) -> CveRecord:
    cve = item.get("cve", item)
    rec = CveRecord(id=cve.get("id", ""), published=(cve.get("published") or "")[:10])
    rec.description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {}) or {}

    def primary(entries):
        if not entries:
            return None
        return next((e for e in entries if e.get("type") == "Primary"), entries[0])

    m4 = primary(metrics.get("cvssMetricV40"))
    if m4:
        rec.cvss4 = m4.get("cvssData", {}).get("baseScore")
        rec.cvss4_vector = m4.get("cvssData", {}).get("vectorString", "")
    for key in ("cvssMetricV31", "cvssMetricV30"):
        m3 = primary(metrics.get(key))
        if m3:
            data = m3.get("cvssData", {})
            rec.cvss3, rec.cvss3_vector, rec.cvss3_version = data.get("baseScore"), data.get("vectorString", ""), data.get("version", "")
            rec.severity = data.get("baseSeverity", "")
            break
    m2 = primary(metrics.get("cvssMetricV2"))
    if m2:
        rec.cvss2 = m2.get("cvssData", {}).get("baseScore")
    cwes = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    rec.cwes = cwes
    for ref in cve.get("references", []) or []:
        url = ref.get("url", "")
        if url:
            rec.references.append(url)
            if "Exploit" in (ref.get("tags") or []):
                rec.exploit_refs.append(url)
    return rec


class NvdClient:
    def __init__(self, base_url: str, api_key: str = "", cache: IntelCache | None = None, cache_days: int = 7,
                 timeout: int = 15, session: requests.Session | None = None, offline: bool = False):
        self.base_url = base_url
        self.api_key = api_key
        self.cache = cache
        self.cache_seconds = cache_days * 86400
        self.timeout = timeout
        self.session = session or requests.Session()
        self.offline = offline
        # NVD public limits: 5 requests / 30 s without a key, 50 / 30 s with one.
        self.min_interval = 0.7 if api_key else 6.2
        self._last = 0.0

    def _get(self, params: dict) -> dict:
        key = "nvd:" + "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        if self.cache:
            hit = self.cache.get(key, self.cache_seconds)
            if hit is not None:
                return hit
        if self.offline:
            raise IntelUnavailable("Offline mode: NVD lookups disabled")
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(4):
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.session.get(self.base_url, params=params, headers=headers, timeout=self.timeout)
            except requests.RequestException as exc:
                raise IntelUnavailable(f"NVD API unreachable ({type(exc).__name__}); check internet access or set ENSAT_OFFLINE=1") from exc
            if r.status_code == 404:
                data = {"vulnerabilities": [], "totalResults": 0}
                break
            if r.status_code in (403, 429, 503):
                time.sleep(min(30, 6 * (attempt + 1)))
                continue
            if r.status_code >= 400:
                raise IntelUnavailable(f"NVD returned HTTP {r.status_code}: {r.text[:200]}")
            data = r.json()
            break
        else:
            raise IntelUnavailable("NVD rate limit: retries exhausted (add an NVD_API_KEY for higher limits)")
        if self.cache:
            self.cache.set(key, data)
            for item in data.get("vulnerabilities", []):
                cid = item.get("cve", {}).get("id")
                if cid:
                    self.cache.set(f"cve:{cid}", item)
        return data

    def cves_for_cpe(self, cpe: Cpe, limit: int = 25) -> list[CveRecord]:
        """CVEs affecting this exact product version, verified against NVD's version ranges."""
        if not cpe.has_version:
            return []
        seen: dict[str, CveRecord] = {}
        for cand in candidates(cpe):
            items = self._get({"cpeName": cand.to_23(), "resultsPerPage": 200}).get("vulnerabilities", [])
            if not items:
                items = self._get({"virtualMatchString": cand.to_23(), "resultsPerPage": 200}).get("vulnerabilities", [])
            for item in items:
                cve = item.get("cve", {})
                if cve.get("vulnStatus") == "Rejected" or cve.get("id") in seen:
                    continue
                if cve_affects(cve, cpe):
                    seen[cve["id"]] = parse_cve(item)
            if seen:
                break
        ranked = sorted(seen.values(), key=lambda r: r.base_score, reverse=True)
        return ranked[:limit]

    def get_cve(self, cve_id: str) -> CveRecord | None:
        cve_id = cve_id.strip().upper()
        if self.cache:
            hit = self.cache.get(f"cve:{cve_id}")
            if hit:
                return parse_cve(hit)
        items = self._get({"cveId": cve_id}).get("vulnerabilities", [])
        return parse_cve(items[0]) if items else None

    def search(self, keyword: str, limit: int = 50) -> list[CveRecord]:
        items = self._get({"keywordSearch": keyword.strip(), "resultsPerPage": min(limit, 200)}).get("vulnerabilities", [])
        return [parse_cve(i) for i in items]

    def cached_records(self) -> list[CveRecord]:
        return [parse_cve(i) for i in self.cache.search("cve:")] if self.cache else []
