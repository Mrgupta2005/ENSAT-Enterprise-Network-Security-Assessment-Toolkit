import pytest

from ensat.parser import ParseError, merge_hosts, parse_nmap_xml, parse_scan, scan_metadata

V1_XML = '''<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/><hostnames><hostname name="lab"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4"/></port></ports></host></nmaprun>'''


def test_parse_v1_compatible():
    hosts = parse_nmap_xml(V1_XML)
    assert hosts[0].address == "192.168.1.10"
    assert hosts[0].hostname == "lab"
    assert hosts[0].services[0].port == 80
    assert hosts[0].services[0].service == "http"


def test_parse_rich_host(lab_xml):
    hosts = parse_nmap_xml(lab_xml)
    assert [h.status for h in hosts] == ["up", "up", "down"]
    h = hosts[0]
    assert h.mac == "08:00:27:AA:BB:CC" and h.vendor.startswith("Oracle VirtualBox")
    assert h.user_hostname == "files.lab.local"
    assert h.hostnames == ["files.lab.local", "fileserver.lab.local"]
    assert h.os_name == "Linux 4.15 - 5.8" and h.os_accuracy == 96
    ftp = next(s for s in h.services if s.port == 21)
    assert ftp.cpes == ["cpe:/a:vsftpd:vsftpd:2.3.4"]
    assert "Anonymous FTP login allowed" in ftp.scripts["ftp-anon"]
    assert ftp.banner == "220 (vsFTPd 2.3.4)"
    ssh = next(s for s in h.services if s.port == 22)
    assert len(ssh.cpes) == 2 and ssh.extrainfo == "protocol 2.0"
    assert "smb2-security-mode" in h.scripts
    assert len(h.open_services) == 6  # filtered telnet excluded


def test_merge_tcp_and_udp(lab_xml):
    udp = '''<nmaprun><host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/><ports>
      <port protocol="udp" portid="161"><state state="open" reason="udp-response"/><service name="snmp"/></port></ports></host></nmaprun>'''
    hosts = parse_scan([lab_xml, udp])
    h = next(x for x in hosts if x.address == "192.168.56.10")
    assert any(s.protocol == "udp" and s.port == 161 for s in h.services)
    assert h.mac  # kept from TCP run
    assert merge_hosts([[]]) == []


def test_bad_xml_raises_parse_error():
    with pytest.raises(ParseError):
        parse_nmap_xml("<nmaprun><host>")


def test_metadata(lab_xml):
    meta = scan_metadata(lab_xml)
    assert meta["hosts_up"] == 2 and meta["nmap_version"] == "7.94"
