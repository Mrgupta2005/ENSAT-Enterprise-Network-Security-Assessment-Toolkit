import os
import sys
import tempfile
from pathlib import Path

# Isolate every test run from the user's real data before ensat.config is imported.
_TMP = Path(tempfile.mkdtemp(prefix="ensat-tests-"))
os.environ.update({
    "ENSAT_DATA_DIR": str(_TMP / "data"), "ENSAT_REPORT_DIR": str(_TMP / "reports"), "ENSAT_LOG_DIR": str(_TMP / "logs"),
    "ENSAT_SCOPE_FILE": str(_TMP / "scope.txt"), "ENSAT_OFFLINE": "1", "ENSAT_OPERATOR": "tester", "NVD_API_KEY": "",
})
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from ensat.config import Settings  # noqa: E402
from ensat.db import Database  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def lab_xml() -> str:
    return (FIXTURES / "nmap_lab.xml").read_text(encoding="utf-8")


@pytest.fixture
def cfg(tmp_path) -> Settings:
    s = Settings()
    s.data_dir = tmp_path / "data"
    s.report_dir = tmp_path / "reports"
    s.log_dir = tmp_path / "logs"
    s.db_path = s.data_dir / "ensat.db"
    s.scope_file = tmp_path / "scope.txt"
    s.offline = True
    for d in (s.data_dir, s.report_dir, s.log_dir):
        d.mkdir(parents=True, exist_ok=True)
    return s


@pytest.fixture
def db(cfg) -> Database:
    return Database(cfg.db_path)


class FakeResponse:
    def __init__(self, payload=None, status=200, text=""):
        self._payload, self.status_code, self.text = payload, status, text or str(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    """Routes requests by URL substring / parameter to canned responses and records calls."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, dict(params or {})))
        return self.handler(url, params or {})


def nvd_item(cve_id, score=9.8, vendor="vsftpd", product="vsftpd", version=None, start=None, end_excl=None,
             exploit=False, cwe="CWE-78", v4=None, status="Analyzed"):
    match = {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"}
    if start:
        match["versionStartIncluding"] = start
    if end_excl:
        match["versionEndExcluding"] = end_excl
    metrics = {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": "CRITICAL",
                                                                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}
    if v4 is not None:
        metrics["cvssMetricV40"] = [{"type": "Primary", "cvssData": {"version": "4.0", "baseScore": v4, "vectorString": "CVSS:4.0/AV:N"}}]
    refs = [{"url": f"https://example.org/{cve_id}", "tags": ["Vendor Advisory"]}]
    if exploit:
        refs.append({"url": f"https://exploits.example/{cve_id}", "tags": ["Exploit", "Third Party Advisory"]})
    return {"cve": {"id": cve_id, "vulnStatus": status, "published": "2024-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": f"Test vulnerability {cve_id}."}],
                    "metrics": metrics, "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
                    "references": refs, "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}}
