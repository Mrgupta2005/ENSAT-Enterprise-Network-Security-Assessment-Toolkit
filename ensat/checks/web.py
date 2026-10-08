"""Passive, non-destructive web checks for HTTP/HTTPS services.

Only GET and OPTIONS requests are sent, to the site root and to a handful of
well-known files whose exposure is a common misconfiguration. Nothing is
submitted, fuzzed, brute-forced or exploited.
"""
from __future__ import annotations

import logging
import re
import ssl
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter

from ..models import Finding, Host, Service

log = logging.getLogger("ensat.web")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "ENSAT/2.0 (authorized security assessment)"
OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"

SENSITIVE_PATHS = [
    ("/.git/HEAD", "WEB-GIT-EXPOSED", "Git repository exposed (/.git/)", 7.5,
     lambda r: r.status_code == 200 and r.text.lstrip().startswith("ref: refs/"),
     "Source code, history and embedded secrets can be downloaded.",
     "Block access to /.git/ in the web server and remove the directory from the web root."),
    ("/.env", "WEB-ENV-EXPOSED", "Environment file exposed (/.env)", 8.0,
     lambda r: r.status_code == 200 and "<html" not in r.text[:500].lower()
     and len(re.findall(r"^[A-Z][A-Z0-9_]{2,}\s*=", r.text, re.M)) >= 2,
     "Environment files typically contain database passwords and API keys.",
     "Remove .env from the web root, deny dot-files in the web server, and rotate any exposed secrets."),
    ("/server-status", "WEB-SERVER-STATUS", "Apache server-status page exposed", 5.0,
     lambda r: r.status_code == 200 and "Apache Server Status" in r.text,
     "Reveals client IPs, requested URLs and internal virtual hosts.",
     "Restrict mod_status to localhost or remove it."),
    ("/.DS_Store", "WEB-DSSTORE-EXPOSED", "macOS .DS_Store file exposed", 3.0,
     lambda r: r.status_code == 200 and r.content[:8] == b"\x00\x00\x00\x01Bud1",
     "Leaks the names of files and directories on the server.",
     "Delete .DS_Store files from the web root and deny dot-files."),
]

TECH_PATTERNS = [
    (r"wp-content|wp-includes", "WordPress"), (r"Drupal", "Drupal"), (r"Joomla", "Joomla"),
    (r"__VIEWSTATE", "ASP.NET WebForms"), (r"csrfmiddlewaretoken", "Django"), (r"laravel_session", "Laravel"),
    (r"PHPSESSID", "PHP"), (r"JSESSIONID", "Java Servlet"), (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"connect\.sid", "Express (Node.js)"), (r"_next/static", "Next.js"), (r"ng-version", "Angular"),
    (r"data-reactroot|react-dom", "React"), (r"grafana", "Grafana"), (r"jenkins", "Jenkins"),
]


class _LenientTLSAdapter(HTTPAdapter):
    """Lets the assessment reach servers with weak/legacy TLS so their problems can be reported."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        params, pool_kwargs = super().build_connection_pool_key_attributes(request, False, cert)
        pool_kwargs["cert_reqs"] = "CERT_NONE"
        pool_kwargs.pop("ca_certs", None)
        pool_kwargs.pop("ca_cert_dir", None)
        return params, pool_kwargs


# Software versions disclosed in HTTP headers, mapped to CPEs so they feed the CVE lookup.
HEADER_CPES = [
    (r"PHP/(\d+\.\d+\.\d+)", "cpe:/a:php:php:{}"),
    (r"Apache/(\d+\.\d+\.\d+)", "cpe:/a:apache:http_server:{}"),
    (r"nginx/(\d+\.\d+\.\d+)", "cpe:/a:f5:nginx:{}"),
    (r"Microsoft-IIS/(\d+\.\d+)", "cpe:/a:microsoft:internet_information_services:{}"),
    (r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)", "cpe:/a:openssl:openssl:{}"),
    (r"Apache-Coyote/1\.1|Tomcat/(\d+\.\d+\.\d+)", "cpe:/a:apache:tomcat:{}"),
]


def cpes_from_technologies(techs: list[str]) -> list[str]:
    out = []
    blob = " ".join(techs)
    for pattern, template in HEADER_CPES:
        for m in re.finditer(pattern, blob):
            if m.lastindex and m.group(1):
                cpe = template.format(m.group(1))
                if cpe not in out:
                    out.append(cpe)
    return out


def _finding(host: Host, svc: Service, check_id, title, score, evidence, impact, rec, owasp=OWASP_MISCONFIG) -> Finding:
    return Finding(host=host.address, port=svc.port, protocol=svc.protocol, check_id=check_id, title=title,
                   category="web", base_score=score, evidence=evidence, impact=impact, recommendation=rec,
                   service=svc.service, owasp=owasp)


def base_url(host: Host, svc: Service) -> str:
    scheme = "https" if svc.is_tls else "http"
    name = host.user_hostname or host.address
    if ":" in name and not name.startswith("["):
        name = f"[{name}]"
    default = (scheme == "http" and svc.port == 80) or (scheme == "https" and svc.port == 443)
    return f"{scheme}://{name}" + ("" if default else f":{svc.port}")


def fingerprint(resp: requests.Response) -> list[str]:
    techs = []
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        if resp.headers.get(h):
            techs.append(f"{h}: {resp.headers[h]}")
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text[:20000], re.I)
    if m:
        techs.append(f"Generator: {m.group(1)}")
    blob = resp.text[:50000] + " " + " ".join(resp.cookies.keys()) + " " + resp.headers.get("Set-Cookie", "")
    for pattern, name in TECH_PATTERNS:
        if re.search(pattern, blob, re.I) and name not in techs:
            techs.append(name)
    return techs


def analyse_response(host: Host, svc: Service, first: requests.Response, final: requests.Response) -> list[Finding]:
    out: list[Finding] = []
    https = final.url.startswith("https://")
    h = {k.lower(): v for k, v in final.headers.items()}

    if not svc.is_tls:
        loc = first.headers.get("Location", "")
        if not (first.is_redirect and loc.lower().startswith("https://")) and not https:
            out.append(_finding(host, svc, "WEB-NO-HTTPS", "Web service does not enforce HTTPS", 5.0,
                                f"{first.url} answered HTTP {first.status_code} without redirecting to HTTPS",
                                "Traffic, sessions and credentials can be intercepted or modified in transit.",
                                "Serve the site over HTTPS and redirect all HTTP requests (301) to HTTPS.",
                                owasp="A02:2021 Cryptographic Failures"))

    if https and "strict-transport-security" not in h:
        out.append(_finding(host, svc, "WEB-HSTS-MISSING", "HSTS header missing", 4.0, f"{final.url} has no Strict-Transport-Security header",
                            "Browsers can be downgraded to HTTP by an attacker on the network (SSL stripping).",
                            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
    is_html = "html" in h.get("content-type", "").lower() or "<html" in final.text[:1000].lower()
    if is_html:
        csp = h.get("content-security-policy", "")
        if not csp:
            out.append(_finding(host, svc, "WEB-CSP-MISSING", "Content-Security-Policy header missing", 3.5, f"{final.url}: no CSP header",
                                "Without CSP, cross-site scripting flaws are easier to exploit.",
                                "Define a Content-Security-Policy that restricts script sources.", owasp="A03:2021 Injection"))
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            out.append(_finding(host, svc, "WEB-CLICKJACKING", "No clickjacking protection", 3.5,
                                f"{final.url}: neither X-Frame-Options nor CSP frame-ancestors set",
                                "The site can be framed by a malicious page to trick users into clicking (clickjacking).",
                                "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive."))
        missing = [x for x in ("X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy") if x.lower() not in h]
        if missing:
            out.append(_finding(host, svc, "WEB-HEADERS-MISSING", "Recommended security headers missing", 2.5,
                                f"{final.url} missing: {', '.join(missing)}",
                                "Missing hardening headers weaken browser-side defences (MIME sniffing, referrer leakage).",
                                "Add X-Content-Type-Options: nosniff, a Referrer-Policy and a Permissions-Policy."))

    disclosed = []
    server = h.get("server", "")
    if re.search(r"\d", server):
        disclosed.append(f"Server: {server}")
    for hdr in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if h.get(hdr):
            disclosed.append(f"{hdr.title()}: {h[hdr]}")
    if disclosed:
        out.append(_finding(host, svc, "WEB-VERSION-DISCLOSURE", "Web server discloses software versions", 3.0, "; ".join(disclosed),
                            "Exact versions help attackers pick matching exploits.",
                            "Suppress version banners (e.g. ServerTokens Prod, server_tokens off, remove X-Powered-By)."))

    weak_cookies = []
    raw_cookies = final.raw.headers.getlist("Set-Cookie") if hasattr(final.raw, "headers") and hasattr(final.raw.headers, "getlist") else \
        ([final.headers["Set-Cookie"]] if "Set-Cookie" in final.headers else [])
    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        problems = [flag for flag, ok in (("Secure", "secure" in low or not https), ("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low)) if not ok]
        if problems:
            weak_cookies.append(f"{name} (missing {', '.join(problems)})")
    if weak_cookies:
        out.append(_finding(host, svc, "WEB-COOKIE-FLAGS", "Cookies set without security attributes", 4.0, "; ".join(weak_cookies)[:400],
                            "Session cookies may be stolen via XSS, sent over HTTP or used in cross-site requests.",
                            "Set Secure, HttpOnly and SameSite on session cookies.", owasp="A07:2021 Identification and Authentication Failures"))

    if re.search(r"<title>\s*(Index of /|Directory listing for /)", final.text[:5000], re.I):
        out.append(_finding(host, svc, "WEB-DIR-LISTING", "Directory listing enabled", 5.0, f"{final.url} returns an auto-generated index",
                            "Visitors can browse files that were never meant to be published.",
                            "Disable automatic indexes (Options -Indexes / autoindex off)."))
    return out


def check_web(host: Host, svc: Service, timeout: float = 8.0) -> tuple[list[Finding], dict]:
    url = base_url(host, svc) + "/"
    info: dict = {"url": url, "status": None, "title": "", "technologies": []}
    session = requests.Session()
    session.headers["User-Agent"] = UA
    session.verify = False
    session.trust_env = False  # connect to targets directly, never via an environment proxy
    session.mount("https://", _LenientTLSAdapter())
    try:
        first = session.get(url, timeout=timeout, allow_redirects=False)
        final = first
        hops = 0
        while final.is_redirect and hops < 5:
            nxt = urljoin(final.url, final.headers.get("Location", ""))
            if urlparse(nxt).hostname not in {urlparse(url).hostname, host.address, host.hostname}:
                break
            final = session.get(nxt, timeout=timeout, allow_redirects=False)
            hops += 1
    except requests.RequestException as exc:
        log.info("Web check of %s failed: %s", url, exc)
        return [], info

    findings = analyse_response(host, svc, first, final)
    info.update(status=final.status_code, url=final.url)
    t = re.search(r"<title[^>]*>(.*?)</title>", final.text[:20000], re.I | re.S)
    info["title"] = re.sub(r"\s+", " ", t.group(1)).strip()[:200] if t else ""
    info["technologies"] = fingerprint(final)
    if info["technologies"]:
        findings.append(_finding(host, svc, "WEB-TECH-FINGERPRINT", "Web technology fingerprint", 0.0,
                                 "; ".join(info["technologies"])[:500], "Informational: technologies identified on the site.",
                                 "Keep the listed components patched and track them in your software inventory.", owasp=""))

    try:
        opt = session.options(url, timeout=timeout, allow_redirects=False)
        allow = opt.headers.get("Allow", "") + "," + opt.headers.get("Public", "")
        risky = sorted({m for m in ("TRACE", "PUT", "DELETE", "TRACK") if re.search(rf"\b{m}\b", allow, re.I)})
        if risky:
            findings.append(_finding(host, svc, "WEB-RISKY-METHODS", "Risky HTTP methods advertised", 4.0, f"Allow: {allow.strip(',')}",
                                     "TRACE enables cross-site tracing; PUT/DELETE may allow content modification if not authenticated.",
                                     "Disable unused HTTP methods in the web server configuration."))
    except requests.RequestException:
        pass

    # Each validator checks the response *content*, so servers that answer 200 to everything
    # (soft-404s) do not produce false positives.
    root = base_url(host, svc)
    for path, cid, title, score, validator, impact, rec in SENSITIVE_PATHS:
        try:
            r = session.get(root + path, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if validator(r):
            findings.append(_finding(host, svc, cid, title, score, f"GET {root}{path} -> HTTP {r.status_code}", impact, rec))
    return findings, info
