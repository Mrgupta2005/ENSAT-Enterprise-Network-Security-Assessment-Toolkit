from ensat.models import Finding, severity_for
from ensat.risk import AssetContext, assess, asset_risk, is_internet_facing, risk_index, score_finding


def cve(**kw):
    base = dict(host="10.0.0.5", port=443, protocol="tcp", check_id="CVE", title="t", category="vulnerability", base_score=9.8, cve="CVE-2099-1")
    base.update(kw)
    return Finding(**base)


def test_worst_case_is_critical_priority():
    f = score_finding(cve(epss=0.92, kev=True), AssetContext("critical", "high", True))
    assert f.risk_score == 10.0 and f.severity == "Critical"
    assert any("KEV" in x for x in f.risk_factors) and any("EPSS 92%" in x for x in f.risk_factors)


def test_context_lowers_and_raises():
    low = score_finding(cve(base_score=7.5, epss=0.001), AssetContext("low", "low", False))
    assert low.risk_score == 5.5 and low.severity == "Medium"
    high = score_finding(cve(base_score=6.5), AssetContext("critical", "medium", True))
    assert high.risk_score == 8.5 and high.severity == "High"


def test_kev_floor():
    f = score_finding(cve(base_score=7.2, kev=True), AssetContext("low", "low", False))
    assert f.risk_score >= 9.0 and f.severity == "Critical"


def test_info_findings_stay_info():
    f = score_finding(cve(base_score=0.0, check_id="WEB-TECH-FINGERPRINT", cve=None), AssetContext("critical", "high", True))
    assert f.severity == "Info" and f.risk_score == 0.0


def test_priority_order_and_helpers():
    a = cve(base_score=5.0, host="10.0.0.1")
    b = cve(base_score=9.1, host="10.0.0.2")
    c = cve(base_score=9.1, host="10.0.0.3", kev=True)
    ordered = assess([a, b, c], {})
    assert ordered[0] is c and ordered[-1] is a
    assert severity_for(9.0) == "Critical" and severity_for(6.9) == "Medium" and severity_for(0) == "Info"
    assert risk_index({"Critical": 1, "High": 2, "Medium": 1, "Low": 2}) == 23
    assert is_internet_facing("8.8.8.8") and not is_internet_facing("192.168.1.1")
    assert asset_risk([9.0, 7.5, 7.0]) == 9.3 and asset_risk([]) == 0.0
