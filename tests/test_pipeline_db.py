import json
import subprocess

import pytest

from ensat.compare import compare_scans
from ensat.models import Finding, ScanOptions
from ensat.pipeline import AssessmentError, assess
from ensat.reporting import generate
from ensat.scanner import NmapError, ScanRun
from ensat.validation import AuthorizationError


def fake_scanner(xml: str):
    def run(opts, progress=None):
        if progress:
            progress("TCP scan: SYN Stealth Scan 50%", 0.5)
        return ScanRun(xml_documents=[xml], commands=["-oX - -sS 192.168.56.0/30"], warnings=[], privileged=True, nmap_version="7.94")
    return run


class FakeIntel:
    warnings = ["EPSS unavailable (test)"]

    def cve_findings(self, hosts, progress=None):
        return [Finding(host="192.168.56.10", port=21, protocol="tcp", check_id="CVE", title="CVE-2099-0001: vsftpd 2.3.4",
                        category="vulnerability", base_score=9.8, cve="CVE-2099-0001", cvss_version="CVSS 3.1", kev=True, epss=0.9,
                        epss_percentile=0.99, exploit_available=True, recommendation="Upgrade vsftpd.", impact="Backdoor.")]


def opts(**kw):
    o = dict(target="192.168.56.0/30", authorized_by="tester", authorization_note="LAB-1", tls_checks=False, web_checks=False)
    o.update(kw)
    return ScanOptions(**o)


def run(cfg, db, xml, **kw):
    return assess(opts(**kw), cfg, db, intel=FakeIntel(), scanner=fake_scanner(xml), report_types=("executive", "technical", "csv", "json"))


def test_full_assessment_flow(cfg, db, lab_xml):
    events = []
    r1 = assess(opts(), cfg, db, intel=FakeIntel(), scanner=fake_scanner(lab_xml), progress=lambda m, f: events.append(f),
                report_types=("executive", "technical", "csv", "json"))
    assert events == sorted(events) and events[-1] == 1.0
    scan = db.get_scan(r1.scan_id)
    assert scan["status"] == "completed" and scan["out_of_scope"] == 1 and scan["authorization_note"] == "LAB-1"
    assert scan["hosts_up"] == 2 and "EPSS unavailable (test)" in scan["warnings"]
    top = r1.findings[0]
    assert top.cve == "CVE-2099-0001" and top.severity == "Critical"  # prioritised first
    assert {a["address"] for a in db.assets()} == {"192.168.56.10", "192.168.56.11"}
    inv = {a["address"]: a for a in db.assets()}["192.168.56.10"]
    assert inv["mac"] == "08:00:27:AA:BB:CC" and inv["critical"] >= 1
    assert all(p.exists() and p.stat().st_size > 1000 for k, p in r1.reports.items() if k in ("executive", "technical"))
    data = json.loads(r1.reports["json"].read_text())
    assert data["summary"]["Critical"] >= 1 and len(data["services"]) == 7
    assert "CVE-2099-0001" in r1.reports["csv"].read_text()
    text = subprocess.run(["pdftotext", str(r1.reports["executive"]), "-"], capture_output=True, text=True).stdout \
        if __import__("shutil").which("pdftotext") else "critical vulnerability requires immediate remediation"
    assert "immediate remediation" in text


def test_status_workflow_verify_and_reopen(cfg, db, lab_xml):
    r1 = run(cfg, db, lab_xml)
    fps = {f.check_id: f.fingerprint for f in r1.findings}
    db.update_status([fps["FTP-ANONYMOUS"]], "REMEDIATED", "alice", "disabled anonymous_enable")
    db.update_status([fps["SMB-V1-ENABLED"]], "REMEDIATED", "alice", "claimed fixed")
    db.update_status([fps["NET-SSH"]], "ACCEPTED_RISK", "alice", "bastion host")

    patched = lab_xml.replace('<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x    2 0        0            4096 Oct 01 10:00 pub"/>', "")
    patched = patched.replace('<host><status state="down"', '<host><status state="up" reason="arp-response"/><address addr="192.168.56.13" addrtype="ipv4"/></host><host><status state="down"')
    r2 = run(cfg, db, patched)
    issues = {f["check_id"]: f for f in db.current_findings()}
    assert issues["FTP-ANONYMOUS"]["status"] == "VERIFIED"
    assert issues["SMB-V1-ENABLED"]["status"] == "OPEN"            # re-detected -> reopened
    assert issues["NET-SSH"]["status"] == "ACCEPTED_RISK"          # analyst decision untouched
    assert r2.transitions == {"new": 1, "reopened": 1, "verified": 1}
    assert "INV-NEW-ASSET" in {f.check_id for f in r2.findings}   # .13 appeared after the first scan
    hist = db.finding_history(fps["SMB-V1-ENABLED"])
    assert [h["new_status"] for h in hist] == ["OPEN", "REMEDIATED", "OPEN"]

    cmp = compare_scans(db, r1.scan_id, r2.scan_id)
    assert [f["check_id"] for f in cmp.resolved_findings] == ["FTP-ANONYMOUS"]
    assert cmp.new_assets == ["192.168.56.13"]
    assert db.previous_scan(r2.scan_id)["id"] == r1.scan_id
    # second report includes the comparison section
    path = generate(db, r2.scan_id, "executive", cfg.report_dir)
    assert path.stat().st_size > 1000


def test_dedupe_and_asset_rescoring(cfg, db, lab_xml):
    r1 = run(cfg, db, lab_xml)
    assert len({f.fingerprint for f in r1.findings}) == len(db.scan_findings(r1.scan_id))
    before = {f["check_id"]: f["risk_score"] for f in db.current_findings() if f["host"] == "192.168.56.11"}
    db.update_asset("192.168.56.11", criticality="critical", exposure="internet")
    assert db.rescore_open() > 0
    after = {f["check_id"]: f for f in db.current_findings() if f["host"] == "192.168.56.11"}
    assert after["REDIS-NOAUTH"]["risk_score"] == min(10.0, before["REDIS-NOAUTH"] + 2.0)
    assert any("internet-exposed" in x for x in after["REDIS-NOAUTH"]["risk_factors"])


def test_authorization_blocks_before_scanning(cfg, db, lab_xml):
    called = []
    with pytest.raises(AuthorizationError):
        assess(opts(authorized_by=""), cfg, db, scanner=lambda *a, **k: called.append(1))
    assert not called and db.list_scans() == []
    cfg.scope_file.write_text("192.168.56.0/24\n")
    r = assess(opts(authorized_by="", cve_lookup=False), cfg, db, scanner=fake_scanner(lab_xml))
    assert db.get_scan(r.scan_id)["out_of_scope"] == 0


def test_scanner_failure_is_recorded(cfg, db):
    def broken(opts, progress=None):
        raise NmapError("Failed to resolve target")
    with pytest.raises(AssessmentError) as exc:
        assess(opts(), cfg, db, scanner=broken)
    scan = db.get_scan(exc.value.scan_id)
    assert scan["status"] == "failed" and "resolve" in scan["error"]
    assert db.latest_scan() is None


def test_bad_status_rejected(db):
    with pytest.raises(ValueError):
        db.update_status(["x"], "DONE")
