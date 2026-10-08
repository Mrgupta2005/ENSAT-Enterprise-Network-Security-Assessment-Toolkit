import datetime
import http.server
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ensat.checks.tls import check_tls, evaluate_certificate
from ensat.checks.web import base_url, check_web, cpes_from_technologies
from ensat.models import Host, Service


class LabHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            body = b"<html><head><title>Index of /</title><meta name='generator' content='WordPress 6.1'></head><body>wp-content</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.49 (Unix)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.send_header("Set-Cookie", "PHPSESSID=abc; Path=/")
        elif self.path == "/.git/HEAD":
            body = b"ref: refs/heads/main\n"
            self.send_response(200)
        elif self.path == "/.env":  # soft-404 style HTML page must NOT be reported
            body = b"<html><body>Not here</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        else:
            body = b"nope"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()


def _serve(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


@pytest.fixture
def http_server():
    srv = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), LabHandler))
    yield srv
    srv.shutdown()


@pytest.fixture
def tls_server(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intranet.lab.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - datetime.timedelta(days=400)).not_valid_after(now - datetime.timedelta(days=3))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("intranet.lab.local")]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                        serialization.NoEncryption()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    yield _serve(srv)
    srv.shutdown()


def test_tls_certificate_checks(tls_server):
    port = tls_server.server_address[1]
    host = Host("127.0.0.1", status="up", user_hostname="files.lab.local")
    findings, cert = check_tls(host, Service(port, service="https", tunnel="ssl"))
    found = {f.check_id for f in findings}
    assert cert["subject"] == "intranet.lab.local" and cert["key_bits"] == 2048
    assert {"TLS-CERT-EXPIRED", "TLS-CERT-SELF-SIGNED", "TLS-HOSTNAME-MISMATCH"} <= found
    assert "TLS-WEAK-KEY" not in found
    assert "TLS-WEAK-PROTOCOL" not in found  # modern server only speaks TLS 1.2+


def test_certificate_rules_offline():
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = {"subject": "a", "issuer": "CA", "self_signed": False, "not_before": None, "sans": ["*.example.com"],
            "not_after": now + datetime.timedelta(days=10), "key": "RSA 1024", "key_bits": 1024, "key_type": "RSA", "signature_hash": "sha1"}
    host = Host("10.0.0.1", user_hostname="www.example.com")
    found = {f.check_id for f in evaluate_certificate(host, Service(443), cert, now)}
    assert found == {"TLS-CERT-EXPIRING", "TLS-WEAK-KEY", "TLS-WEAK-SIGNATURE"}  # wildcard SAN matches


def test_nmap_ssl_enum_fallback():
    out = "| ssl-enum-ciphers:\n|   TLSv1.0:\n|     ciphers:\n|   TLSv1.2:\n|_  least strength: C"
    host = Host("192.0.2.1", status="up")  # unreachable TEST-NET address: only Nmap output is used
    findings, _ = check_tls(host, Service(1, service="https", tunnel="ssl", scripts={"ssl-enum-ciphers": out}), timeout=0.5, probe_protocols=False)
    found = {f.check_id: f for f in findings}
    assert "TLSv1.0" in found["TLS-WEAK-PROTOCOL"].evidence
    assert "TLS-WEAK-CIPHERS" in found


def test_web_checks(http_server):
    port = http_server.server_address[1]
    host = Host("127.0.0.1", status="up")
    findings, info = check_web(host, Service(port, service="http"))
    found = {f.check_id for f in findings}
    assert {"WEB-NO-HTTPS", "WEB-CSP-MISSING", "WEB-CLICKJACKING", "WEB-HEADERS-MISSING", "WEB-VERSION-DISCLOSURE",
            "WEB-COOKIE-FLAGS", "WEB-DIR-LISTING", "WEB-GIT-EXPOSED", "WEB-RISKY-METHODS", "WEB-TECH-FINGERPRINT"} <= found
    assert "WEB-ENV-EXPOSED" not in found     # HTML soft-404 is not a leaked .env
    assert "WEB-HSTS-MISSING" not in found    # HSTS only applies to HTTPS
    assert info["title"] == "Index of /"
    assert "WordPress" in info["technologies"] and "PHP" in info["technologies"]
    assert "cpe:/a:apache:http_server:2.4.49" in cpes_from_technologies(info["technologies"])


def test_https_web_checks_reach_untrusted_cert(tls_server):
    port = tls_server.server_address[1]
    findings, info = check_web(Host("127.0.0.1", status="up"), Service(port, service="https", tunnel="ssl"))
    assert info["status"] == 200
    assert "WEB-HSTS-MISSING" in {f.check_id for f in findings}
    assert "WEB-NO-HTTPS" not in {f.check_id for f in findings}


def test_base_url():
    assert base_url(Host("10.0.0.1"), Service(80, service="http")) == "http://10.0.0.1"
    assert base_url(Host("10.0.0.1"), Service(8443, service="https", tunnel="ssl")) == "https://10.0.0.1:8443"
    assert base_url(Host("::1"), Service(8080, service="http")) == "http://[::1]:8080"
