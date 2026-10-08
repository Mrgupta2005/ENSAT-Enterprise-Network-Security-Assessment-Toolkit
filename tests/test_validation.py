import pytest

from ensat.validation import AuthorizationError, ValidationError, check_authorization, in_scope, load_scope, parse_target, parse_targets, validate_ports


@pytest.mark.parametrize("raw,kind,count", [
    ("192.168.1.10", "ip", 1), ("10.0.0.0/24", "network", 256), ("10.0.0.5-20", "range", 16),
    ("server.lab.local", "hostname", 1), ("::1", "ip", 1), ("10.0.0.7/32", "ip", 1),
])
def test_parse_valid_targets(raw, kind, count):
    t = parse_target(raw)
    assert t.kind == kind and t.host_count == count


@pytest.mark.parametrize("raw", ["-sV", "--script=x", "10.0.0.1;rm", "a b", "10.0.0.300", "10.0.0.20-5", "$(id)", "10.0.0.0/33", "999.1.1.1"])
def test_reject_malicious_or_malformed_targets(raw):
    with pytest.raises(ValidationError):
        parse_target(raw)


def test_multiple_targets_and_host_limit():
    assert len(parse_targets("10.0.0.1, 10.0.0.2 10.0.0.3")) == 3
    with pytest.raises(ValidationError):
        parse_targets("10.0.0.0/16", max_hosts=1024)


@pytest.mark.parametrize("ports", ["22", "22,80,443", "1-1024", "T:80,U:53", " 22, 80 "])
def test_valid_ports(ports):
    assert validate_ports(ports)


@pytest.mark.parametrize("ports", ["0", "70000", "80-20", "22;id", "abc", "-p-"])
def test_invalid_ports(ports):
    with pytest.raises(ValidationError):
        validate_ports(ports)


def test_scope_enforcement(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# lab\n192.168.56.0/24\n*.lab.local  # wildcard\n", encoding="utf-8")
    scope = load_scope(scope_file)
    assert in_scope(parse_target("192.168.56.10"), scope)
    assert in_scope(parse_target("192.168.56.0/25"), scope)
    assert in_scope(parse_target("files.lab.local"), scope)
    assert in_scope(parse_target("127.0.0.1"), scope)  # loopback always allowed
    assert not in_scope(parse_target("192.168.57.1"), scope)
    assert not in_scope(parse_target("192.168.56.0/23"), scope)

    with pytest.raises(AuthorizationError):
        check_authorization(parse_targets("8.8.8.8"), scope, acknowledged=False)
    outside = check_authorization(parse_targets("8.8.8.8 192.168.56.4"), scope, acknowledged=True)
    assert [t.raw for t in outside] == ["8.8.8.8"]
