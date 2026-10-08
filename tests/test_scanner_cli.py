import shutil

import pytest

from ensat import cli
from ensat.models import ScanOptions
from ensat.scanner import PROGRESS_RE, build_commands
from ensat.validation import ValidationError

needs_nmap = pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")


@needs_nmap
def test_build_commands_unprivileged():
    cmds, warnings = build_commands(ScanOptions(target="10.0.0.5", os_detection=True, udp=True), privileged=False)
    assert len(cmds) == 1
    cmd = cmds[0]
    assert "-sT" in cmd and "-Pn" in cmd and "-O" not in cmd and cmd[-1] == "10.0.0.5"
    assert "--script" in cmd and "ftp-anon" in cmd[cmd.index("--script") + 1]
    assert any("OS detection" in w for w in warnings) and any("UDP" in w for w in warnings)


@needs_nmap
def test_build_commands_privileged_full():
    cmds, _ = build_commands(ScanOptions(target="10.0.0.0/24", profile="full", os_detection=True, udp=True, ports="22,80"), privileged=True)
    tcp, udp = cmds
    assert "-sS" in tcp and "-O" in tcp and "-Pn" not in tcp  # discovery kept for subnets
    assert tcp[tcp.index("-p") + 1] == "22,80"
    assert "-sU" in udp


@needs_nmap
def test_build_commands_rejects_injection():
    with pytest.raises(ValidationError):
        build_commands(ScanOptions(target="--script=evil 10.0.0.1"), privileged=False)
    with pytest.raises(ValidationError):
        build_commands(ScanOptions(target="10.0.0.1", ports="80 --script x"), privileged=False)


def test_progress_regex():
    m = PROGRESS_RE.search('<taskprogress task="Service scan" time="1" percent="66.67" remaining="3"/>')
    assert m.group(1) == "Service scan" and m.group(2) == "66.67"


def test_cli_parser_and_v1_flags():
    p = cli.build_parser()
    a = p.parse_args(["scan", "127.0.0.1", "--ports", "22,80", "--service-detection"])
    assert a.func is cli.cmd_assess and a.ports == "22,80"
    s = p.parse_args(["status", "in_progress", "abc123", "--note", "ticket"])
    assert s.new_status == "IN_PROGRESS"


def test_cli_commands_on_empty_db(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(cli.settings, "db_path", tmp_path / "empty.db")
    for argv in (["history"], ["findings"], ["assets"], ["compare"], ["report", "--latest"]):
        with pytest.raises(SystemExit):
            cli.main(argv)
    out = capsys.readouterr().out
    assert "No scans" in out or "No completed scans" in out


def test_cli_rejects_bad_target(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["assess", "8.8.8.8;id", "--no-cve"])
    assert exc.value.code == 2
    assert "Not started" in capsys.readouterr().out


def test_cli_requires_authorization_for_out_of_scope(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["assess", "203.0.113.10", "--no-cve"])
    assert exc.value.code == 2
    assert "not in the authorized scope" in capsys.readouterr().out


def test_cli_commands_with_data(capsys, monkeypatch, cfg, db, lab_xml):
    from test_pipeline_db import run
    run(cfg, db, lab_xml)
    run(cfg, db, lab_xml)
    monkeypatch.setattr(cli.settings, "db_path", cfg.db_path)
    monkeypatch.setattr(cli.settings, "report_dir", cfg.report_dir)
    for argv in (["history"], ["findings", "--severity", "critical"], ["assets"], ["compare"], ["report", "--type", "csv"]):
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        assert exc.value.code == 0, argv
    fp = db.current_findings()[0]["fingerprint"]
    with pytest.raises(SystemExit):
        cli.main(["status", "IN_PROGRESS", fp[:8], "--note", "CHG-1"])
    assert db.current_findings()[0]["status"] == "IN_PROGRESS"
    with pytest.raises(SystemExit):
        cli.main(["assets", "192.168.56.11", "--criticality", "critical", "--known", "yes"])
    out = capsys.readouterr().out
    assert "No change in overall risk" in out and "Updated 1 finding" in out and "re-scored" in out
