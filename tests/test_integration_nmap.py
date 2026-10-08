"""Integration test: real Nmap against a throwaway local web server (skipped if Nmap is missing)."""
import http.server
import shutil
import threading

import pytest

from ensat.models import ScanOptions
from ensat.pipeline import assess

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")]


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def test_real_scan_of_localhost(cfg, db, tmp_path):
    (tmp_path / "index.html").write_text("<html><title>ENSAT test</title></html>")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **k: Handler(*a, directory=str(tmp_path), **k))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        result = assess(ScanOptions(target="127.0.0.1", profile="quick", ports=str(port), cve_lookup=False, timeout=180),
                        cfg, db, report_types=("technical",))
    finally:
        srv.shutdown()
    host = next(h for h in result.hosts if h.address == "127.0.0.1")
    assert host.status == "up"
    assert any(s.port == port for s in host.open_services)
    assert "WEB-NO-HTTPS" in {f.check_id for f in result.findings}
    assert result.reports["technical"].exists()
    assert db.get_scan(result.scan_id)["nmap_version"]
