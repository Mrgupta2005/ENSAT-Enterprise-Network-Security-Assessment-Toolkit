from ensat.checks.network import check_exposure, check_scripts, match_rule
from ensat.models import Host, Service
from ensat.parser import parse_nmap_xml


def ids(findings):
    return {f.check_id for f in findings}


def test_rules_match_service_before_port():
    assert match_rule(Service(3307, service="mysql")).check_id == "NET-DB-MYSQL"     # non-standard port
    assert match_rule(Service(8080, service="http")) is None                          # web handled elsewhere
    assert match_rule(Service(445, service="unknown")).check_id == "NET-SMB"          # port fallback
    assert match_rule(Service(2222, service="ssh")).check_id == "NET-SSH"
    assert match_rule(Service(3389, service="ssl/ms-wbt-server")).check_id == "NET-RDP"


def test_exposure_and_script_findings(lab_xml):
    h, redis_host, _ = parse_nmap_xml(lab_xml)
    found = check_exposure(h) + check_scripts(h)
    assert {"NET-FTP", "NET-SSH", "NET-SMB", "NET-DB-MYSQL", "NET-OPEN-SERVICE",
            "FTP-ANONYMOUS", "SMB-SIGNING-NOT-REQUIRED", "SMB-V1-ENABLED"} <= ids(found)
    assert "NET-TELNET" not in ids(found)  # filtered port is not exposure
    mysql = [f for f in found if f.check_id == "NET-DB-MYSQL"]
    assert {f.port for f in mysql} == {3306, 3307}
    r = check_exposure(redis_host) + check_scripts(redis_host)
    assert {"NET-DB-REDIS", "REDIS-NOAUTH"} <= ids(r)


def test_default_page_and_weak_ssh():
    h = Host("10.0.0.1", status="up", services=[
        Service(80, service="http", scripts={"http-title": "Apache2 Ubuntu Default Page: It works"}),
        Service(22, service="ssh", scripts={"ssh2-enum-algos": "kex_algorithms:\n  diffie-hellman-group1-sha1\nencryption:\n  aes128-ctr"}),
    ])
    found = check_scripts(h)
    assert {"WEB-DEFAULT-PAGE", "SSH-WEAK-ALGOS"} <= ids(found)
    weak = next(f for f in found if f.check_id == "SSH-WEAK-ALGOS")
    assert "diffie-hellman-group1-sha1" in weak.evidence and "aes128-ctr" not in weak.evidence
