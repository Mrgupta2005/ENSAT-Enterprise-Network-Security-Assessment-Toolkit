import json

import pytest
from conftest import FakeResponse, FakeSession, nvd_item

from ensat.intel import ThreatIntel
from ensat.intel.cache import IntelCache
from ensat.intel.cpe import compare_versions, cve_affects, parse_cpe
from ensat.intel.feeds import EpssClient, KevCatalog
from ensat.intel.nvd import IntelUnavailable, NvdClient, parse_cve
from ensat.parser import parse_nmap_xml


def test_cpe_conversion():
    c = parse_cpe("cpe:/a:mysql:mysql:8.0.39")
    assert c.to_23() == "cpe:2.3:a:mysql:mysql:8.0.39:*:*:*:*:*:*:*"
    o = parse_cpe("cpe:/a:openbsd:openssh:7.4p1")
    assert (o.version, o.update) == ("7.4", "p1")
    assert not parse_cpe("cpe:/o:microsoft:windows").has_version
    assert parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").version == "2.4.49"
    assert parse_cpe("garbage") is None


@pytest.mark.parametrize("a,b,expected", [("2.4.49", "2.4.50", -1), ("8.0.39", "8.0.4", 1), ("1.0.2k", "1.0.2", 1),
                                          ("7.4", "7.4.0", 0), ("10.0", "9.9", 1)])
def test_version_compare(a, b, expected):
    assert compare_versions(a, b) == expected


def test_version_ranges():
    cpe = parse_cpe("cpe:/a:apache:http_server:2.4.49")
    hit = nvd_item("CVE-2099-0001", vendor="apache", product="http_server", start="2.4.0", end_excl="2.4.51")["cve"]
    miss = nvd_item("CVE-2099-0002", vendor="apache", product="http_server", end_excl="2.4.10")["cve"]
    exact = nvd_item("CVE-2099-0003", vendor="apache", product="http_server", version="2.4.49")["cve"]
    other = nvd_item("CVE-2099-0004", vendor="nginx", product="nginx")["cve"]
    assert cve_affects(hit, cpe) and cve_affects(exact, cpe)
    assert not cve_affects(miss, cpe) and not cve_affects(other, cpe)


def test_parse_cve_prefers_v4_and_reads_cwe_and_exploits():
    rec = parse_cve(nvd_item("CVE-2099-0005", score=8.1, v4=9.3, exploit=True))
    assert rec.cvss3 == 8.1 and rec.cvss4 == 9.3 and rec.base_score == 9.3 and rec.score_source == "CVSS 4.0"
    assert rec.cwes == ["CWE-78"] and rec.exploit_refs


def test_nvd_alias_fallback_and_cache(tmp_path):
    # MySQL is published under vendor 'oracle' in NVD; the 'mysql:mysql' query returns nothing.
    def handler(url, params):
        key = params.get("cpeName") or params.get("virtualMatchString") or ""
        if ":oracle:mysql:" in key:
            return FakeResponse({"vulnerabilities": [nvd_item("CVE-2099-1000", score=6.5, vendor="oracle", product="mysql", start="8.0.0", end_excl="8.0.40"),
                                                     nvd_item("CVE-2099-1001", score=7.5, vendor="oracle", product="mysql", end_excl="8.0.30"),
                                                     nvd_item("CVE-2099-1002", vendor="oracle", product="mysql", status="Rejected")]})
        return FakeResponse({"vulnerabilities": []})

    session = FakeSession(handler)
    client = NvdClient("https://nvd.test", cache=IntelCache(tmp_path / "c.db"), session=session)
    client.min_interval = 0
    recs = client.cves_for_cpe(parse_cpe("cpe:/a:mysql:mysql:8.0.39"))
    assert [r.id for r in recs] == ["CVE-2099-1000"]  # 1001 fixed before 8.0.39, 1002 rejected
    n = len(session.calls)
    client.cves_for_cpe(parse_cpe("cpe:/a:mysql:mysql:8.0.39"))
    assert len(session.calls) == n  # served from cache
    assert client.get_cve("CVE-2099-1000").cvss3 == 6.5  # cached record


def test_nvd_offline_and_errors(tmp_path):
    offline = NvdClient("https://nvd.test", cache=IntelCache(tmp_path / "c.db"), offline=True)
    with pytest.raises(IntelUnavailable):
        offline.cves_for_cpe(parse_cpe("cpe:/a:x:y:1.0"))
    bad = NvdClient("https://nvd.test", session=FakeSession(lambda u, p: FakeResponse({}, status=500, text="boom")))
    bad.min_interval = 0
    with pytest.raises(IntelUnavailable):
        bad.cves_for_cpe(parse_cpe("cpe:/a:x:y:1.0"))


def test_epss_and_kev(tmp_path):
    epss = EpssClient("https://epss.test", IntelCache(tmp_path / "c.db"),
                      session=FakeSession(lambda u, p: FakeResponse({"data": [{"cve": "CVE-2099-0001", "epss": "0.92", "percentile": "0.99"}]})))
    assert epss.scores(["CVE-2099-0001", "CVE-2099-0002"]) == {"CVE-2099-0001": (0.92, 0.99)}
    kev_file = tmp_path / "kev.json"
    kev = KevCatalog("https://kev.test", kev_file, session=FakeSession(lambda u, p: FakeResponse(
        {"vulnerabilities": [{"cveID": "CVE-2099-0001", "requiredAction": "Apply updates per vendor instructions.", "dueDate": "2099-02-01"}]})))
    assert kev.get("cve-2099-0001")["dueDate"] == "2099-02-01"
    assert json.loads(kev_file.read_text())["vulnerabilities"]
    assert kev.get("CVE-2099-0002") is None


def test_threat_intel_end_to_end(cfg, lab_xml):
    cfg.offline = False

    def handler(url, params):
        if "epss" in url:
            return FakeResponse({"data": [{"cve": "CVE-2099-2000", "epss": "0.92", "percentile": "0.99"}]})
        if "kev" in url:
            return FakeResponse({"vulnerabilities": [{"cveID": "CVE-2099-2000", "requiredAction": "Remove the backdoored build."}]})
        key = params.get("cpeName") or params.get("virtualMatchString") or ""
        if ":vsftpd:vsftpd:2.3.4" in key:
            return FakeResponse({"vulnerabilities": [nvd_item("CVE-2099-2000", score=9.8, version="2.3.4", exploit=True)]})
        return FakeResponse({"vulnerabilities": []})

    cfg.nvd_url, cfg.epss_url, cfg.kev_url = "https://nvd.test", "https://epss.test", "https://kev.test"
    intel = ThreatIntel(cfg, session=FakeSession(handler))
    intel.nvd.min_interval = 0
    findings = intel.cve_findings(parse_nmap_xml(lab_xml))
    f = next(x for x in findings if x.cve == "CVE-2099-2000")
    assert f.port == 21 and f.base_score == 9.8 and f.epss == 0.92 and f.kev and f.exploit_available
    assert f.recommendation.startswith("CISA KEV required action")
    assert f.owasp.startswith("A06")
