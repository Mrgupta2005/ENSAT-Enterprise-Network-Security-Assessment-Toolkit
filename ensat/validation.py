"""Input validation and authorization-scope enforcement.

Every target and port string goes through here before it reaches Nmap, so a
malformed or malicious value (for example one starting with ``-`` that Nmap
would read as an option) can never be passed on.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
OCTET_RANGE_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$")
PORT_TOKEN_RE = re.compile(r"^(?:[TU]:)?(\d{1,5})(?:-(\d{1,5}))?$")


class ValidationError(ValueError):
    """Raised for malformed targets or ports."""


class AuthorizationError(PermissionError):
    """Raised when a target is outside the authorized scope and not acknowledged."""


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str                      # ip | network | range | hostname
    network: ipaddress._BaseNetwork | None = None
    first: ipaddress._BaseAddress | None = None
    last: ipaddress._BaseAddress | None = None

    @property
    def host_count(self) -> int:
        if self.kind == "network":
            return self.network.num_addresses
        if self.kind == "range":
            return int(self.last) - int(self.first) + 1
        return 1

    @property
    def is_loopback(self) -> bool:
        if self.kind == "hostname":
            return self.raw.lower() in {"localhost", "localhost."}
        if self.kind == "network":
            return self.network.is_loopback
        return bool(self.first and self.first.is_loopback and self.last.is_loopback)

    @property
    def is_single_host(self) -> bool:
        return self.host_count == 1


def parse_target(token: str) -> Target:
    token = token.strip()
    if not token:
        raise ValidationError("Empty target")
    if token.startswith("-"):
        raise ValidationError(f"Invalid target '{token}': targets may not start with '-'")
    if any(c in token for c in ";|&$`<>\"' \t\\"):
        raise ValidationError(f"Invalid characters in target '{token}'")
    # single IP
    try:
        ip = ipaddress.ip_address(token)
        return Target(token, "ip", first=ip, last=ip)
    except ValueError:
        pass
    # CIDR
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise ValidationError(f"Invalid network '{token}': {exc}") from exc
        if net.num_addresses == 1:
            return Target(token, "ip", first=net.network_address, last=net.network_address)
        return Target(token, "network", network=net, first=net.network_address, last=net.broadcast_address)
    # 192.168.1.10-50
    m = OCTET_RANGE_RE.match(token)
    if m:
        a, b, c, d, e = (int(x) for x in m.groups())
        if any(x > 255 for x in (a, b, c, d, e)) or e < d:
            raise ValidationError(f"Invalid address range '{token}'")
        return Target(token, "range", first=ipaddress.ip_address(f"{a}.{b}.{c}.{d}"), last=ipaddress.ip_address(f"{a}.{b}.{c}.{e}"))
    if HOSTNAME_RE.match(token) and not token.replace(".", "").isdigit():
        return Target(token, "hostname")
    raise ValidationError(f"Unrecognised target '{token}'. Use an IP, CIDR (10.0.0.0/24), range (10.0.0.1-50) or hostname.")


def parse_targets(text: str, max_hosts: int = 4096) -> list[Target]:
    tokens = [t for t in re.split(r"[,\s]+", text or "") if t]
    if not tokens:
        raise ValidationError("No target supplied")
    targets = [parse_target(t) for t in tokens]
    total = sum(t.host_count for t in targets)
    if total > max_hosts:
        raise ValidationError(f"Target scope covers {total} addresses; the limit is {max_hosts} (set ENSAT_MAX_HOSTS to change it).")
    return targets


def validate_ports(ports: str | None) -> str | None:
    if ports is None or not str(ports).strip():
        return None
    ports = str(ports).replace(" ", "")
    for token in ports.split(","):
        m = PORT_TOKEN_RE.match(token)
        if not m:
            raise ValidationError(f"Invalid port specification '{token}'. Use e.g. 22,80,443 or 1-1024 (optionally T:/U: prefixes).")
        lo = int(m.group(1))
        hi = int(m.group(2) or lo)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
            raise ValidationError(f"Port out of range in '{token}' (1-65535)")
    return ports


# ---------------------------------------------------------------- scope ----

def load_scope(path: Path) -> list[str]:
    if not path or not Path(path).exists():
        return []
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def _entry_covers(entry: str, target: Target) -> bool:
    if target.kind == "hostname":
        return fnmatch.fnmatch(target.raw.lower().rstrip("."), entry.lower().rstrip("."))
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    if target.first.version != net.version:
        return False
    return target.first in net and target.last in net


def in_scope(target: Target, scope: list[str]) -> bool:
    if target.is_loopback:
        return True
    return any(_entry_covers(e, target) for e in scope)


def check_authorization(targets: list[Target], scope: list[str], acknowledged: bool) -> list[Target]:
    """Return the targets that are outside scope. Raise if any are and no acknowledgement was given."""
    outside = [t for t in targets if not in_scope(t, scope)]
    if outside and not acknowledged:
        names = ", ".join(t.raw for t in outside)
        raise AuthorizationError(
            f"{names} {'is' if len(outside) == 1 else 'are'} not in the authorized scope file. "
            "Add it to scope.txt, or confirm you have written authorization to assess it "
            "(--authorized on the CLI / the confirmation box in the dashboard)."
        )
    return outside
