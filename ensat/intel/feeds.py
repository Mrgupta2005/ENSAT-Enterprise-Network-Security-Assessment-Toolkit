"""FIRST EPSS scores and the CISA Known Exploited Vulnerabilities (KEV) catalog."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import requests

from .cache import IntelCache
from .nvd import IntelUnavailable

log = logging.getLogger("ensat.feeds")


class EpssClient:
    def __init__(self, url: str, cache: IntelCache | None = None, timeout: int = 15,
                 session: requests.Session | None = None, offline: bool = False, cache_hours: int = 24):
        self.url, self.cache, self.timeout = url, cache, timeout
        self.session = session or requests.Session()
        self.offline = offline
        self.max_age = cache_hours * 3600

    def scores(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        """Return {cve: (probability 0-1, percentile 0-1)}."""
        out: dict[str, tuple[float, float]] = {}
        todo = []
        for cid in dict.fromkeys(c.upper() for c in cve_ids if c):
            hit = self.cache.get(f"epss:{cid}", self.max_age) if self.cache else None
            if hit is not None:
                if hit:
                    out[cid] = tuple(hit)
            else:
                todo.append(cid)
        if todo and self.offline:
            return out
        for i in range(0, len(todo), 80):
            batch = todo[i:i + 80]
            try:
                r = self.session.get(self.url, params={"cve": ",".join(batch)}, timeout=self.timeout)
                r.raise_for_status()
                data = r.json().get("data", [])
            except (requests.RequestException, ValueError) as exc:
                raise IntelUnavailable(f"FIRST EPSS API unreachable ({type(exc).__name__})") from exc
            got = {d["cve"].upper(): (float(d.get("epss", 0)), float(d.get("percentile", 0))) for d in data if d.get("cve")}
            out.update(got)
            if self.cache:
                for cid in batch:
                    self.cache.set(f"epss:{cid}", list(got[cid]) if cid in got else [])
        return out


class KevCatalog:
    def __init__(self, url: str, cache_path: Path, max_age_hours: int = 24, timeout: int = 30,
                 session: requests.Session | None = None, offline: bool = False):
        self.url, self.cache_path, self.timeout = url, Path(cache_path), timeout
        self.max_age = max_age_hours * 3600
        self.session = session or requests.Session()
        self.offline = offline
        self._entries: dict[str, dict] | None = None

    @property
    def age_hours(self) -> float | None:
        if not self.cache_path.exists():
            return None
        return (time.time() - self.cache_path.stat().st_mtime) / 3600

    def refresh(self) -> int:
        try:
            r = self.session.get(self.url, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError) as exc:
            raise IntelUnavailable(f"CISA KEV catalog unreachable ({type(exc).__name__})") from exc
        self.cache_path.write_text(json.dumps(data), encoding="utf-8")
        self._entries = None
        return len(data.get("vulnerabilities", []))

    def _load(self) -> dict[str, dict]:
        if self._entries is not None:
            return self._entries
        stale = self.age_hours is None or self.age_hours * 3600 > self.max_age
        if stale and not self.offline:
            try:
                self.refresh()
            except IntelUnavailable as exc:
                log.warning("%s (using cached copy if present)", exc)
        entries = {}
        if self.cache_path.exists():
            try:
                data = json.loads(self.cache_path.read_text(encoding="utf-8"))
                entries = {v["cveID"].upper(): v for v in data.get("vulnerabilities", []) if v.get("cveID")}
            except (ValueError, KeyError) as exc:
                log.warning("KEV cache unreadable: %s", exc)
        self._entries = entries
        return entries

    def get(self, cve_id: str) -> dict | None:
        return self._load().get(cve_id.upper())

    def __len__(self) -> int:
        return len(self._load())
