"""Convert Nmap XML into ENSAT models."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .models import Host, Service


class ParseError(ValueError):
    pass


def _scripts(parent) -> dict[str, str]:
    out = {}
    if parent is None:
        return out
    for s in parent.findall("script"):
        sid = s.get("id")
        if sid:
            out[sid] = (s.get("output") or "").strip()
    return out


def _parse_host(h) -> Host:
    status_el = h.find("status")
    host = Host(address="unknown", status=status_el.get("state", "unknown") if status_el is not None else "unknown")
    for a in h.findall("address"):
        kind = a.get("addrtype", "")
        if kind == "mac":
            host.mac = a.get("addr", "")
            host.vendor = a.get("vendor", "")
        elif host.address == "unknown":
            host.address = a.get("addr", "unknown")
            host.addr_type = kind or "ipv4"
    names = [hn.get("name", "") for hn in h.findall("hostnames/hostname") if hn.get("name")]
    host.hostnames = list(dict.fromkeys(names))
    host.hostname = host.hostnames[0] if host.hostnames else ""
    host.user_hostname = next((hn.get("name", "") for hn in h.findall("hostnames/hostname") if hn.get("type") == "user"), "")

    best = None
    for m in h.findall("os/osmatch"):
        acc = int(m.get("accuracy", "0") or 0)
        if best is None or acc > best[1]:
            best = (m, acc)
    if best is not None:
        host.os_name, host.os_accuracy = best[0].get("name", ""), best[1]
        host.os_cpes = [c.text for c in best[0].findall("osclass/cpe") if c.text]

    for p in h.findall("ports/port"):
        state_el = p.find("state")
        svc_el = p.find("service")
        g = svc_el.get if svc_el is not None else (lambda k, d="": d)
        scripts = _scripts(p)
        svc = Service(
            port=int(p.get("portid", 0)),
            protocol=p.get("protocol", "tcp"),
            state=state_el.get("state", "unknown") if state_el is not None else "unknown",
            reason=state_el.get("reason", "") if state_el is not None else "",
            service=g("name", ""),
            product=g("product", ""),
            version=g("version", ""),
            extrainfo=g("extrainfo", ""),
            tunnel=g("tunnel", ""),
            cpes=[c.text for c in svc_el.findall("cpe") if c.text] if svc_el is not None else [],
            scripts=scripts,
            banner=scripts.get("banner", ""),
        )
        if not host.os_name and g("ostype", ""):
            host.os_name = g("ostype", "")
        host.services.append(svc)
    host.scripts = _scripts(h.find("hostscript"))
    return host


def parse_nmap_xml(xml: str) -> list[Host]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ParseError(f"Nmap returned XML that could not be parsed: {exc}") from exc
    return [_parse_host(h) for h in root.findall("host")]


def merge_hosts(groups: list[list[Host]]) -> list[Host]:
    """Merge hosts from several Nmap runs (e.g. TCP + UDP) by address."""
    merged: dict[str, Host] = {}
    for hosts in groups:
        for h in hosts:
            cur = merged.get(h.address)
            if cur is None:
                merged[h.address] = h
                continue
            if h.status == "up":
                cur.status = "up"
            for attr in ("hostname", "user_hostname", "mac", "vendor", "os_name"):
                if not getattr(cur, attr) and getattr(h, attr):
                    setattr(cur, attr, getattr(h, attr))
            cur.hostnames = list(dict.fromkeys(cur.hostnames + h.hostnames))
            seen = {(s.port, s.protocol) for s in cur.services}
            cur.services += [s for s in h.services if (s.port, s.protocol) not in seen]
            cur.scripts.update(h.scripts)
    hosts = list(merged.values())
    for h in hosts:
        h.services.sort(key=lambda s: (s.protocol, s.port))
    return sorted(hosts, key=lambda h: _addr_key(h.address))


def _addr_key(addr: str):
    import ipaddress
    try:
        ip = ipaddress.ip_address(addr)
        return (ip.version, int(ip))
    except ValueError:
        return (9, 0)


def parse_scan(xml_documents: list[str]) -> list[Host]:
    return merge_hosts([parse_nmap_xml(x) for x in xml_documents])


def scan_metadata(xml: str) -> dict:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {}
    finished = root.find("runstats/finished")
    hosts = root.find("runstats/hosts")
    return {
        "args": root.get("args", ""),
        "nmap_version": root.get("version", ""),
        "start": root.get("startstr", ""),
        "elapsed": finished.get("elapsed", "") if finished is not None else "",
        "hosts_up": int(hosts.get("up", 0)) if hosts is not None else 0,
        "hosts_total": int(hosts.get("total", 0)) if hosts is not None else 0,
    }
