"""TLS/SSL certificate and protocol checks (passive: a normal handshake only)."""
from __future__ import annotations

import fnmatch
import logging
import re
import socket
import ssl
from datetime import datetime, timedelta, timezone

from ..models import Finding, Host, Service

log = logging.getLogger("ensat.tls")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:  # pragma: no cover
    x509 = None

OWASP_CRYPTO = "A02:2021 Cryptographic Failures"
EXPIRY_WARNING_DAYS = 30


def _finding(host: Host, svc: Service, check_id, title, score, evidence, impact, rec) -> Finding:
    return Finding(host=host.address, port=svc.port, protocol=svc.protocol, check_id=check_id, title=title,
                   category="tls", base_score=score, evidence=evidence, impact=impact, recommendation=rec,
                   service=svc.service, owasp=OWASP_CRYPTO)


def _context(min_v=None, max_v=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if min_v:
        ctx.minimum_version = min_v
    if max_v:
        ctx.maximum_version = max_v
    return ctx


def fetch_certificate(address: str, port: int, timeout: float = 6.0, sni: str | None = None) -> tuple[bytes, str, str]:
    """Return (DER certificate, negotiated protocol, cipher name)."""
    with socket.create_connection((address, port), timeout=timeout) as sock:
        with _context().wrap_socket(sock, server_hostname=sni or None) as tls:
            return tls.getpeercert(binary_form=True), tls.version() or "", (tls.cipher() or ("",))[0]


def probe_protocol(address: str, port: int, version: ssl.TLSVersion, timeout: float = 6.0) -> bool | None:
    """True = server accepted this protocol, False = refused, None = could not test locally."""
    try:
        ctx = _context(version, version)
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as tls:
                return tls.version() is not None
    except ssl.SSLError as exc:
        msg = str(exc).lower()
        if "no protocols available" in msg or "no_protocols_available" in msg:
            return None  # our local OpenSSL refuses to speak this version
        return False
    except (OSError, ValueError):
        return False


def describe_cert(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)

    def cn(name):
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()

    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, key_bits, key_type = f"RSA {key.key_size}", key.key_size, "RSA"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, key_bits, key_type = f"EC {key.curve.name}", key.key_size, "EC"
    elif isinstance(key, dsa.DSAPublicKey):
        key_desc, key_bits, key_type = f"DSA {key.key_size}", key.key_size, "DSA"
    else:
        key_desc, key_bits, key_type = type(key).__name__, 0, "other"
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    return {
        "subject": cn(cert.subject), "issuer": cn(cert.issuer), "self_signed": cert.issuer == cert.subject,
        "not_before": cert.not_valid_before_utc, "not_after": cert.not_valid_after_utc, "sans": sans,
        "key": key_desc, "key_bits": key_bits, "key_type": key_type, "signature_hash": sig,
        "serial": format(cert.serial_number, "x"),
    }


def name_matches(name: str, cert: dict) -> bool:
    candidates = cert["sans"] or [cert["subject"]]
    name = name.lower().rstrip(".")
    return any(fnmatch.fnmatch(name, c.lower()) for c in candidates)


def _parse_nmap_ssl_cert(output: str) -> dict | None:
    m = re.search(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})T?(\d{2}:\d{2}:\d{2})?", output)
    if not m:
        return None
    after = datetime.fromisoformat(f"{m.group(1)}T{m.group(2) or '00:00:00'}").replace(tzinfo=timezone.utc)
    subj = re.search(r"Subject:\s*(?:commonName=)?([^\n/]+)", output)
    issuer = re.search(r"Issuer:\s*(?:commonName=)?([^\n/]+)", output)
    bits = re.search(r"Public Key bits:\s*(\d+)", output)
    ktype = re.search(r"Public Key type:\s*(\w+)", output)
    sig = re.search(r"Signature Algorithm:\s*(\w+)", output)
    s, i = (subj.group(1).strip() if subj else ""), (issuer.group(1).strip() if issuer else "")
    return {"subject": s, "issuer": i, "self_signed": bool(s) and s == i, "not_before": None, "not_after": after, "sans": [],
            "key": f"{(ktype.group(1) if ktype else '').upper()} {bits.group(1) if bits else ''}".strip(),
            "key_bits": int(bits.group(1)) if bits else 0, "key_type": (ktype.group(1).upper() if ktype else ""),
            "signature_hash": (sig.group(1).lower().replace("withrsaencryption", "") if sig else "unknown"), "serial": ""}


def evaluate_certificate(host: Host, svc: Service, cert: dict, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    after = cert["not_after"]
    ev = f"Subject: {cert['subject']}; Issuer: {cert['issuer']}; Valid until: {after:%Y-%m-%d}; Key: {cert['key']}"
    if after < now:
        out.append(_finding(host, svc, "TLS-CERT-EXPIRED", "TLS certificate has expired", 6.5,
                            ev + f" (expired {(now - after).days} days ago)",
                            "Clients will show security warnings; users learn to click through them, enabling interception.",
                            "Renew the certificate and automate renewal (e.g. ACME/Let's Encrypt or your internal CA)."))
    elif after - now < timedelta(days=EXPIRY_WARNING_DAYS):
        out.append(_finding(host, svc, "TLS-CERT-EXPIRING", "TLS certificate expires soon", 4.0,
                            ev + f" (expires in {(after - now).days} days)",
                            "An expired certificate will break clients and cause an outage.",
                            "Renew the certificate before it expires and monitor expiry dates."))
    if cert.get("not_before") and cert["not_before"] > now:
        out.append(_finding(host, svc, "TLS-CERT-NOT-YET-VALID", "TLS certificate is not yet valid", 4.0, ev,
                            "Clients will reject the certificate.", "Check the issuing CA and the server clock."))
    if cert["self_signed"]:
        out.append(_finding(host, svc, "TLS-CERT-SELF-SIGNED", "Self-signed TLS certificate", 5.0, ev,
                            "Clients cannot verify the server's identity, which permits man-in-the-middle attacks.",
                            "Use a certificate issued by a trusted public or internal CA."))
    if cert["key_type"] == "RSA" and 0 < cert["key_bits"] < 2048 or cert["key_type"] == "DSA":
        out.append(_finding(host, svc, "TLS-WEAK-KEY", "Weak certificate key", 7.0, ev,
                            "Short RSA or DSA keys can be factored or are deprecated.",
                            "Reissue the certificate with RSA >= 2048 bits or an ECDSA P-256 key."))
    if cert["signature_hash"] in {"sha1", "md5", "md2"}:
        out.append(_finding(host, svc, "TLS-WEAK-SIGNATURE", f"Certificate signed with {cert['signature_hash'].upper()}", 6.0, ev,
                            "SHA-1/MD5 signatures are vulnerable to collision attacks and rejected by modern browsers.",
                            "Reissue the certificate with a SHA-256 (or stronger) signature."))
    if host.user_hostname and (cert["sans"] or cert["subject"]) and not name_matches(host.user_hostname, cert):
        out.append(_finding(host, svc, "TLS-HOSTNAME-MISMATCH", "Certificate does not match the host name", 5.0,
                            ev + f"; expected {host.user_hostname}; SANs: {', '.join(cert['sans'][:8]) or 'none'}",
                            "Clients will reject the connection or users will be trained to ignore warnings.",
                            "Issue a certificate whose SAN list covers every name the service is reached by."))
    return out


def _weak_from_nmap(output: str) -> tuple[list[str], str]:
    protos = re.findall(r"^\|?\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1):", output, re.M)
    grade = re.search(r"least strength:\s*([A-F])", output)
    return sorted(set(protos)), (grade.group(1) if grade else "")


def check_tls(host: Host, svc: Service, timeout: float = 6.0, probe_protocols: bool = True) -> tuple[list[Finding], dict | None]:
    findings: list[Finding] = []
    cert = None
    negotiated = ""
    if x509 is not None:
        try:
            der, negotiated, cipher = fetch_certificate(host.address, svc.port, timeout, host.user_hostname or None)
            cert = describe_cert(der)
            cert["protocol"], cert["cipher"] = negotiated, cipher
        except (OSError, ssl.SSLError, ValueError) as exc:
            log.info("TLS handshake with %s:%s failed: %s", host.address, svc.port, exc)
    if cert is None and "ssl-cert" in svc.scripts:
        cert = _parse_nmap_ssl_cert(svc.scripts["ssl-cert"])
    if cert:
        findings += evaluate_certificate(host, svc, cert)

    weak: set[str] = set()
    enum = svc.scripts.get("ssl-enum-ciphers", "")
    grade = ""
    if enum:
        protos, grade = _weak_from_nmap(enum)
        weak.update(protos)
    if probe_protocols and (cert is not None or negotiated):
        for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            if probe_protocol(host.address, svc.port, ver, timeout):
                weak.add(label)
    if weak:
        findings.append(_finding(host, svc, "TLS-WEAK-PROTOCOL", "Deprecated TLS/SSL protocol versions enabled", 6.5,
                                 "Server accepts: " + ", ".join(sorted(weak)),
                                 "SSLv3/TLS 1.0/TLS 1.1 are deprecated (RFC 8996) and vulnerable to downgrade and padding-oracle attacks.",
                                 "Allow only TLS 1.2 and TLS 1.3."))
    if grade and grade in "CDEF":
        findings.append(_finding(host, svc, "TLS-WEAK-CIPHERS", f"Weak TLS cipher suites (Nmap grade {grade})", 5.5,
                                 f"ssl-enum-ciphers least strength: {grade}",
                                 "Weak or export-grade ciphers can allow traffic decryption.",
                                 "Restrict cipher suites to AEAD ciphers with forward secrecy (ECDHE + AES-GCM/ChaCha20)."))
    return findings, cert
