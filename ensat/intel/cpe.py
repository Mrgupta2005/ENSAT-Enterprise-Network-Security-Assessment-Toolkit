"""CPE helpers: Nmap's CPE 2.2 URIs -> CPE 2.3 names, vendor aliases, version comparison."""
from __future__ import annotations

import re
from dataclasses import dataclass

# Nmap and NVD sometimes disagree on vendor/product naming. Each key maps to
# extra candidates to try (the original is always tried first).
ALIASES: dict[tuple[str, str], list[tuple[str, str]]] = {
    ("mysql", "mysql"): [("oracle", "mysql"), ("oracle", "mysql_server")],
    ("oracle", "mysql"): [("oracle", "mysql_server")],
    ("igor_sysoev", "nginx"): [("f5", "nginx"), ("nginx", "nginx")],
    ("nginx", "nginx"): [("f5", "nginx")],
    ("microsoft", "iis"): [("microsoft", "internet_information_services")],
    ("microsoft", "internet_information_server"): [("microsoft", "internet_information_services")],
    ("openbsd", "openssh"): [],
    ("postgresql", "postgresql"): [],
    ("apache", "httpd"): [("apache", "http_server")],
    ("proftpd", "proftpd"): [("proftpd_project", "proftpd")],
    ("vsftpd", "vsftpd"): [("beasts", "vsftpd")],
    ("samba", "samba"): [],
    ("redis", "redis"): [],
    ("isc", "bind"): [],
}


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"

    @property
    def has_version(self) -> bool:
        return self.version not in ("", "*", "-")

    def to_23(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version or '*'}:{self.update or '*'}:*:*:*:*:*:*"

    def with_vendor_product(self, vendor: str, product: str) -> "Cpe":
        return Cpe(self.part, vendor, product, self.version, self.update)


def parse_cpe(value: str) -> Cpe | None:
    """Accept either 'cpe:/a:vendor:product:version' (2.2) or 'cpe:2.3:a:...' (2.3)."""
    if not value:
        return None
    value = value.strip()
    if value.startswith("cpe:2.3:"):
        parts = re.split(r"(?<!\\):", value)[2:]
    elif value.startswith("cpe:/"):
        parts = value[5:].split(":")
    else:
        return None
    parts = [p.replace("%2b", "+").replace("~", "") for p in parts] + ["*"] * 5
    part, vendor, product, version, update = parts[:5]
    if not (part and vendor and product):
        return None
    version = version or "*"
    # Nmap packs OpenSSH-style "7.4p1" in the version; NVD splits it into version + update.
    m = re.match(r"^(\d+(?:\.\d+)*)(p\d+)$", version)
    if m and update in ("", "*"):
        version, update = m.group(1), m.group(2)
    return Cpe(part.lower(), vendor.lower(), product.lower(), version, update or "*")


def candidates(cpe: Cpe) -> list[Cpe]:
    out = [cpe]
    for vendor, product in ALIASES.get((cpe.vendor, cpe.product), []):
        out.append(cpe.with_vendor_product(vendor, product))
    return out


PRE_RELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "dev", "preview"}


def _vparts(v: str) -> list:
    """Split a version into comparable parts. Letter suffixes such as OpenSSL's '1.0.2k' sort
    after the plain release; pre-release tags (alpha/beta/rc) sort before it."""
    parts = []
    for tok in re.split(r"[.\-_+]", v.lower()):
        for sub in re.findall(r"\d+|[a-z]+", tok):
            if sub.isdigit():
                parts.append((0, int(sub)))
            else:
                parts.append((-1 if sub in PRE_RELEASE else 1, sub))
    return parts


def compare_versions(a: str, b: str) -> int:
    """Tolerant version comparison. Returns -1, 0 or 1."""
    pa, pb = _vparts(a), _vparts(b)
    n = max(len(pa), len(pb))
    pa += [(0, 0)] * (n - len(pa))
    pb += [(0, 0)] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def version_in_range(version: str, match: dict) -> bool:
    """Evaluate one NVD cpeMatch entry's version bounds against ``version``."""
    criteria = parse_cpe(match.get("criteria", ""))
    if criteria and criteria.has_version:
        return compare_versions(version, criteria.version) == 0
    checks = [
        ("versionStartIncluding", lambda c: c >= 0), ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0), ("versionEndExcluding", lambda c: c < 0),
    ]
    for key, ok in checks:
        bound = match.get(key)
        if bound and not ok(compare_versions(version, bound)):
            return False
    return True  # within all bounds (or no bounds + wildcard version = every version affected)


def cve_affects(cve: dict, cpe: Cpe) -> bool:
    """True if any vulnerable cpeMatch in the CVE's configurations covers this product/version."""
    configs = cve.get("configurations") or []
    if not configs:
        return True  # nothing to check against; trust NVD's match
    names = {(c.vendor, c.product) for c in candidates(cpe)}
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                crit = parse_cpe(match.get("criteria", ""))
                if crit and (crit.vendor, crit.product) in names and version_in_range(cpe.version, match):
                    return True
    return False
