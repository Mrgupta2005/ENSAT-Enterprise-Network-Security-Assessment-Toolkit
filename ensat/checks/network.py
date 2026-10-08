"""Network-exposure and misconfiguration checks.

Rules match on the *service Nmap identified* first and only fall back to the
port number when the service is unknown, so MySQL on 3307 is still treated as
a database and something harmless on 8080 is not mislabelled.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Finding, Host, Service

GENERIC_NAMES = {"", "unknown", "tcpwrapped"}


@dataclass(frozen=True)
class Rule:
    check_id: str
    title: str
    score: float
    services: frozenset
    ports: frozenset
    impact: str
    recommendation: str
    owasp: str = "A05:2021 Security Misconfiguration"
    protocol: str = "tcp"


def _r(check_id, title, score, services, ports, impact, rec, protocol="tcp", owasp="A05:2021 Security Misconfiguration"):
    return Rule(check_id, title, score, frozenset(services), frozenset(ports), impact, rec, owasp, protocol)


EXPOSURE_RULES: list[Rule] = [
    _r("NET-TELNET", "Telnet service exposed", 8.0, {"telnet"}, {23},
       "Credentials and session data cross the network in clear text and can be captured.",
       "Disable Telnet and use SSH for remote administration.", owasp="A02:2021 Cryptographic Failures"),
    _r("NET-RSERVICES", "Legacy r-services exposed (rsh/rlogin/rexec)", 9.0, {"shell", "login", "exec", "rsh", "rlogin", "rexec"}, {512, 513, 514},
       "Legacy remote shells rely on host-based trust and clear-text credentials.",
       "Disable r-services entirely and replace them with SSH."),
    _r("NET-FTP", "FTP service exposed", 6.5, {"ftp"}, {21},
       "FTP sends credentials and files unencrypted.",
       "Replace FTP with SFTP/FTPS or restrict it to a trusted management network.", owasp="A02:2021 Cryptographic Failures"),
    _r("NET-SMB", "SMB file sharing exposed", 8.0, {"microsoft-ds", "smb"}, {445},
       "SMB is a frequent target for worms, ransomware and credential relay attacks.",
       "Restrict SMB (445) to trusted internal segments, block it at the perimeter and keep hosts patched."),
    _r("NET-NETBIOS", "NetBIOS session service exposed", 6.0, {"netbios-ssn"}, {139},
       "NetBIOS leaks host/user information and exposes legacy SMB transport.",
       "Disable NetBIOS over TCP/IP where it is not required and segment legacy file sharing."),
    _r("NET-MSRPC", "Microsoft RPC endpoint mapper exposed", 5.0, {"msrpc"}, {135},
       "The RPC endpoint mapper reveals service information and is a common lateral-movement path.",
       "Block TCP/135 between untrusted segments and from the internet; allow it only where Windows management requires it."),
    _r("NET-RDP", "Remote Desktop (RDP) exposed", 8.0, {"ms-wbt-server", "rdp"}, {3389},
       "Exposed RDP is a leading initial-access vector (brute force, credential stuffing, RDP CVEs).",
       "Place RDP behind a VPN or RD Gateway, enforce NLA and MFA, and restrict source addresses."),
    _r("NET-VNC", "VNC remote desktop exposed", 8.5, {"vnc", "vnc-http"}, {5900, 5901, 5902, 5903},
       "VNC often uses weak or no authentication and unencrypted sessions.",
       "Remove VNC exposure or tunnel it over SSH/VPN with strong authentication."),
    _r("NET-X11", "X11 display server exposed", 8.0, {"x11"}, {6000, 6001},
       "An open X server can allow screen capture and keystroke injection.",
       "Disable TCP listening for X11 (-nolisten tcp) and use SSH X forwarding."),
    _r("NET-DB-MYSQL", "MySQL/MariaDB database exposed", 8.0, {"mysql"}, {3306},
       "A directly reachable database invites credential attacks and exploitation of server flaws.",
       "Bind the database to localhost/application networks and allow access only from application servers."),
    _r("NET-DB-MSSQL", "Microsoft SQL Server exposed", 8.0, {"ms-sql-s", "ms-sql"}, {1433},
       "A directly reachable database invites credential attacks and exploitation of server flaws.",
       "Restrict SQL Server to application/management networks and disable the SQL Browser if unused."),
    _r("NET-DB-POSTGRES", "PostgreSQL database exposed", 8.0, {"postgresql"}, {5432},
       "A directly reachable database invites credential attacks and exploitation of server flaws.",
       "Restrict pg_hba.conf and firewall rules to application hosts only."),
    _r("NET-DB-ORACLE", "Oracle TNS listener exposed", 8.0, {"oracle-tns", "oracle"}, {1521},
       "The TNS listener exposes the database to remote attacks.",
       "Restrict the listener to application networks and enable listener security."),
    _r("NET-DB-MONGO", "MongoDB exposed", 8.5, {"mongodb", "mongod"}, {27017},
       "Exposed MongoDB instances are routinely mass-scanned and ransomed.",
       "Bind MongoDB to internal interfaces and enable authentication (security.authorization)."),
    _r("NET-DB-REDIS", "Redis exposed", 8.5, {"redis"}, {6379},
       "Redis is often deployed without authentication and can be abused for remote code execution.",
       "Bind Redis to localhost/internal networks, enable protected-mode and requirepass/ACLs."),
    _r("NET-DB-ELASTIC", "Elasticsearch exposed", 8.0, {"elasticsearch", "wap-wsp"}, {9200},
       "Exposed Elasticsearch clusters frequently leak entire datasets.",
       "Enable Elastic security (authentication + TLS) and restrict network access."),
    _r("NET-DB-MEMCACHED", "Memcached exposed", 7.5, {"memcache", "memcached"}, {11211},
       "Memcached has no authentication by default and can be abused for amplification attacks.",
       "Bind Memcached to localhost and disable UDP."),
    _r("NET-DOCKER", "Docker Engine API exposed", 9.5, {"docker"}, {2375},
       "An unauthenticated Docker API gives full root-equivalent control of the host.",
       "Never expose the Docker socket over TCP without mutual TLS; prefer SSH or local socket access."),
    _r("NET-K8S-KUBELET", "Kubernetes kubelet API exposed", 8.0, {"kubelet"}, {10250},
       "The kubelet API can allow command execution in containers if misconfigured.",
       "Restrict kubelet access to the control plane and disable anonymous authentication."),
    _r("NET-K8S-API", "Kubernetes API server exposed", 7.0, {"kubernetes"}, {6443},
       "An exposed control plane widens the attack surface of the whole cluster.",
       "Restrict API server access to administrators via VPN/allow-lists."),
    _r("NET-WINRM", "Windows Remote Management (WinRM) exposed", 7.0, {"wsman", "wsmans"}, {5985, 5986},
       "WinRM provides remote PowerShell and is used for lateral movement.",
       "Limit WinRM to management hosts and require HTTPS (5986) with Kerberos/certificate auth."),
    _r("NET-LDAP", "LDAP directory service exposed", 6.0, {"ldap"}, {389},
       "Clear-text LDAP can leak directory data and credentials.",
       "Require LDAPS/StartTLS and LDAP signing; restrict access to domain members.", owasp="A02:2021 Cryptographic Failures"),
    _r("NET-NFS", "NFS exposed", 7.0, {"nfs", "nfs_acl"}, {2049},
       "Misconfigured NFS exports can expose or allow modification of file systems.",
       "Restrict exports to specific hosts and use root_squash."),
    _r("NET-RPCBIND", "RPC portmapper exposed", 5.0, {"rpcbind"}, {111},
       "rpcbind reveals RPC services and can be abused for amplification.",
       "Block rpcbind from untrusted networks or disable it if NFS/RPC is unused."),
    _r("NET-SMTP", "SMTP mail service exposed", 4.0, {"smtp", "submission"}, {25, 587},
       "Mail services can be abused for relay or user enumeration if misconfigured.",
       "Confirm the server is not an open relay and that VRFY/EXPN are disabled."),
    _r("NET-MAIL-CLEARTEXT", "Clear-text mail retrieval (POP3/IMAP)", 5.0, {"pop3", "imap"}, {110, 143},
       "Mailbox credentials may be sent without encryption.",
       "Use POP3S/IMAPS (995/993) or enforce STARTTLS and disable plain-text authentication.", owasp="A02:2021 Cryptographic Failures"),
    _r("NET-DNS", "DNS service exposed", 4.0, {"domain"}, {53},
       "DNS servers can leak internal names or be abused for amplification if recursion is open.",
       "Restrict recursion to internal clients and disable zone transfers to unauthorised hosts."),
    _r("NET-SNMP", "SNMP exposed", 7.0, {"snmp"}, {161},
       "SNMP v1/v2c uses community strings that are often default ('public') and leak configuration.",
       "Disable SNMP v1/v2c, use SNMPv3 with authPriv, and restrict access to monitoring hosts.", protocol="udp"),
    _r("NET-IPMI", "IPMI/BMC exposed", 8.0, {"asf-rmcp", "ipmi"}, {623},
       "IPMI 2.0 allows offline password-hash retrieval and full out-of-band control of the server.",
       "Place BMC interfaces on an isolated management VLAN.", protocol="udp"),
    _r("NET-TFTP", "TFTP exposed", 6.5, {"tftp"}, {69},
       "TFTP has no authentication and may serve configuration files.",
       "Disable TFTP or restrict it to provisioning networks.", protocol="udp"),
    _r("NET-UPNP", "UPnP/SSDP exposed", 5.0, {"upnp", "ssdp"}, {1900},
       "SSDP leaks device details and is abused for amplification attacks.",
       "Disable UPnP on servers and block SSDP at network boundaries."),
    _r("NET-WSD", "Web Services for Devices (WSD) exposed", 3.0, {"wsdapi"}, {5357},
       "WSD advertises device information to the network.",
       "Disable network discovery on servers or restrict it to trusted segments."),
    _r("NET-SSH", "SSH remote administration exposed", 3.0, {"ssh"}, {22},
       "SSH is secure by design but exposed instances attract brute-force attempts.",
       "Use key-based authentication, disable root and password login, and restrict source addresses.", owasp=""),
]

DEFAULT_PAGE_PATTERNS = [
    (r"Apache2? (Ubuntu|Debian)? ?Default Page", "Apache default page"),
    (r"Welcome to nginx", "nginx default page"),
    (r"IIS Windows Server|Internet Information Services", "IIS default page"),
    (r"Test Page for the (Apache|Nginx) HTTP Server", "Web server test page"),
    (r"Apache Tomcat(/[\d.]+)?$", "Tomcat default page"),
    (r"It works!", "Apache default page"),
]

WEAK_SSH_ALGOS = ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "arcfour", "3des-cbc",
                  "blowfish-cbc", "hmac-md5", "hmac-sha1-96", "ssh-dss"]


def _evidence(svc: Service) -> str:
    parts = [f"{svc.protocol.upper()}/{svc.port}", svc.service or "unknown", svc.product, svc.version, svc.extrainfo]
    return " ".join(p for p in parts if p).strip()


def match_rule(svc: Service) -> Rule | None:
    name = svc.service.lower()
    if name.startswith("ssl/"):
        name = name[4:]
    for rule in EXPOSURE_RULES:
        if name in rule.services:
            return rule
    if name in GENERIC_NAMES:
        for rule in EXPOSURE_RULES:
            if svc.port in rule.ports and rule.protocol == svc.protocol:
                return rule
    return None


def _finding(host: Host, svc: Service, check_id, title, score, evidence, impact, rec, category="misconfiguration",
             owasp="A05:2021 Security Misconfiguration") -> Finding:
    return Finding(host=host.address, port=svc.port, protocol=svc.protocol, check_id=check_id, title=title,
                   category=category, base_score=score, evidence=evidence, impact=impact, recommendation=rec,
                   service=svc.service, owasp=owasp)


def check_exposure(host: Host) -> list[Finding]:
    findings: list[Finding] = []
    for svc in host.open_services:
        rule = match_rule(svc)
        if rule:
            findings.append(_finding(host, svc, rule.check_id, rule.title, rule.score, _evidence(svc),
                                     rule.impact, rule.recommendation, category="exposure", owasp=rule.owasp))
        elif not svc.is_http:  # HTTP services are assessed by the web checks
            findings.append(_finding(
                host, svc, "NET-OPEN-SERVICE", f"Open service: {svc.service or 'unknown'}", 2.0, _evidence(svc),
                "Every listening service adds attack surface.",
                "Confirm the service is required, patched, authenticated and restricted to the networks that need it.",
                category="exposure", owasp=""))
    return findings


def check_scripts(host: Host) -> list[Finding]:
    """Turn safe-NSE script output into concrete misconfiguration findings."""
    findings: list[Finding] = []
    for svc in host.open_services:
        sc = svc.scripts
        out = sc.get("ftp-anon", "")
        if "Anonymous FTP login allowed" in out:
            findings.append(_finding(host, svc, "FTP-ANONYMOUS", "Anonymous FTP login allowed", 7.5,
                                     out.splitlines()[0][:300],
                                     "Anyone can log in without credentials and read (possibly write) files.",
                                     "Disable anonymous access (anonymous_enable=NO) unless the server is an intentional public mirror."))
        if "redis-info" in sc and re.search(r"Version", sc["redis-info"], re.I):
            findings.append(_finding(host, svc, "REDIS-NOAUTH", "Redis accepts unauthenticated commands", 9.0,
                                     sc["redis-info"][:300],
                                     "Unauthenticated Redis can be used to read/write data and often to execute code on the host.",
                                     "Enable requirepass/ACLs and protected-mode; bind to localhost.", owasp="A07:2021 Identification and Authentication Failures"))
        mongo = sc.get("mongodb-info", "")
        if mongo and "version" in mongo.lower() and "authentication" not in mongo.lower() and "error" not in mongo.lower():
            findings.append(_finding(host, svc, "MONGODB-NOAUTH", "MongoDB returns server information without authentication", 9.0,
                                     mongo[:300], "The database may be readable by anyone who can reach it.",
                                     "Enable MongoDB authorization and bind to internal interfaces.", owasp="A07:2021 Identification and Authentication Failures"))
        ssh = sc.get("ssh2-enum-algos", "")
        weak = sorted({a for a in WEAK_SSH_ALGOS if re.search(rf"\b{re.escape(a)}\b", ssh)})
        if weak:
            findings.append(_finding(host, svc, "SSH-WEAK-ALGOS", "SSH server supports weak algorithms", 5.0,
                                     "Weak algorithms offered: " + ", ".join(weak),
                                     "Weak key-exchange, cipher or MAC algorithms reduce the protection of SSH sessions.",
                                     "Remove the listed algorithms from sshd_config (KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms).",
                                     category="tls", owasp="A02:2021 Cryptographic Failures"))
        title = sc.get("http-title", "")
        for pattern, label in DEFAULT_PAGE_PATTERNS:
            if title and re.search(pattern, title, re.I):
                findings.append(_finding(host, svc, "WEB-DEFAULT-PAGE", f"Default web server page ({label})", 4.0,
                                         f"Page title: {title[:200]}",
                                         "Default installations reveal software details and suggest an unmanaged or forgotten server.",
                                         "Remove default content or decommission the service if it is not needed.", category="web"))
                break

    # host-level scripts (SMB, DNS)
    hs = host.scripts
    smb_port = next((s for s in host.open_services if s.port in (445, 139)), None)
    sm = hs.get("smb2-security-mode", "")
    if smb_port and "not required" in sm.lower():
        findings.append(_finding(host, smb_port, "SMB-SIGNING-NOT-REQUIRED", "SMB signing not required", 6.0,
                                 sm.replace("\n", " ")[:300],
                                 "Without mandatory signing, SMB traffic can be relayed (NTLM relay) to compromise hosts.",
                                 "Enable 'Digitally sign communications (always)' via Group Policy for clients and servers."))
    proto = hs.get("smb-protocols", "")
    if smb_port and re.search(r"SMBv1|NT LM 0\.12", proto):
        findings.append(_finding(host, smb_port, "SMB-V1-ENABLED", "SMBv1 protocol enabled", 8.5,
                                 "smb-protocols reports the SMBv1 dialect (NT LM 0.12)",
                                 "SMBv1 is deprecated and was the vector for EternalBlue/WannaCry.",
                                 "Disable SMBv1 (Disable-WindowsOptionalFeature -FeatureName SMB1Protocol) and remove the feature."))
    for svc in host.open_services:
        dns = svc.scripts.get("dns-recursion", "")
        if "Recursion appears to be enabled" in dns:
            findings.append(_finding(host, svc, "DNS-OPEN-RECURSION", "DNS server allows recursion", 6.5, dns[:200],
                                     "Open resolvers can be abused for DNS amplification attacks and cache poisoning.",
                                     "Limit recursion to internal client networks (allow-recursion)."))
    return findings
