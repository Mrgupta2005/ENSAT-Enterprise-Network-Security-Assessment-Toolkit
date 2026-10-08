"""Plain data models shared by every ENSAT layer."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = worse
STATUSES = ["OPEN", "IN_PROGRESS", "REMEDIATED", "VERIFIED", "ACCEPTED_RISK", "FALSE_POSITIVE"]
CLOSED_STATUSES = {"REMEDIATED", "VERIFIED", "ACCEPTED_RISK", "FALSE_POSITIVE"}
CRITICALITY_LEVELS = ["critical", "high", "medium", "low"]


def severity_for(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""          # "ssl" when Nmap detected TLS wrapping
    cpes: list[str] = field(default_factory=list)
    reason: str = ""
    banner: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def cpe(self) -> Optional[str]:
        return self.cpes[0] if self.cpes else None

    @property
    def is_tls(self) -> bool:
        name = self.service.lower()
        return self.tunnel == "ssl" or name in {"https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps"} or name.startswith("ssl/") \
            or "ssl-cert" in self.scripts

    @property
    def is_http(self) -> bool:
        name = self.service.lower()
        return name.startswith("http") or name in {"https-alt", "http-proxy", "ssl/http"} or "http-title" in self.scripts

    @property
    def label(self) -> str:
        return " ".join(x for x in (self.product, self.version) if x).strip() or self.service or "unknown"


@dataclass
class Host:
    address: str
    addr_type: str = "ipv4"
    hostname: str = ""
    hostnames: list[str] = field(default_factory=list)
    user_hostname: str = ""   # the name the operator typed, if they scanned by hostname
    status: str = "unknown"
    mac: str = ""
    vendor: str = ""
    os_name: str = ""
    os_accuracy: int = 0
    os_cpes: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)  # host-level NSE output

    @property
    def open_services(self) -> list[Service]:
        return [s for s in self.services if s.state in ("open", "open|filtered")]


@dataclass
class Finding:
    host: str
    port: Optional[int]
    protocol: str
    check_id: str                 # e.g. "NET-SMB-EXPOSED", "TLS-CERT-EXPIRED", "CVE"
    title: str
    category: str                 # exposure | misconfiguration | tls | web | vulnerability | inventory
    base_score: float             # CVSS for CVEs, rule score for checks (0-10)
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    service: str = ""
    cve: Optional[str] = None
    cvss_version: str = ""
    cvss_vector: str = ""
    cvss3: Optional[float] = None
    cvss4: Optional[float] = None
    cwe: str = ""
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = False
    exploit_available: bool = False
    owasp: str = ""
    references: list[str] = field(default_factory=list)
    # set by the risk engine
    risk_score: float = 0.0
    severity: str = "Info"
    risk_factors: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable identity used for de-duplication and status tracking across scans."""
        key = "|".join([self.host, str(self.port or ""), self.protocol or "", self.check_id, self.cve or ""])
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ScanOptions:
    target: str
    profile: str = "standard"            # quick | standard | full
    ports: Optional[str] = None
    service_detection: bool = True
    os_detection: bool = False
    udp: bool = False
    skip_discovery: Optional[bool] = None  # None = automatic (skip for single hosts)
    nse_scripts: bool = True
    tls_checks: bool = True
    web_checks: bool = True
    cve_lookup: bool = True
    timeout: int = 1800
    authorized_by: str = ""
    authorization_note: str = ""
