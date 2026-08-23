"""
tests/test_xml_security.py
==========================
Nmap XML Parser Resilience & Security Tests.
Verifies parser safety against malformed, corrupted, or non-conforming XML documents.
"""

import pytest
from services.parser import parse_nmap_xml, InvalidNmapXMLError

MALFORMED_XML_SAMPLES = [
    "",  # Empty string
    "   ",  # Whitespace only
    "This is plain text, not XML",
    "<?xml version='1.0'?><unclosed_tag>",
    "<?xml version='1.0'?><not_nmap_root><data>123</data></not_nmap_root>",
    "<?xml version='1.0'?>\x00\x01\x02<corrupted_bytes>",
    "<nmaprun><host><ports><port></unmatched></ports></host></nmaprun>",
]

VALID_NMAP_XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80 192.168.1.10" start="1718012345" version="7.94">
<host starttime="1718012345" endtime="1718012350">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
        <hostname name="vuln-node.lab" type="user"/>
    </hostnames>
    <os>
        <osmatch name="Linux 5.4" accuracy="95"/>
    </os>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu-4ubuntu0.5"/>
            <script id="ssh2-enum-algos" output="Supported algos: curve25519-sha256, ecdh-sha2-nistp256"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4.41"/>
            <script id="http-title" output="Welcome to Apache"/>
        </port>
        <port protocol="tcp" portid="443">
            <state state="closed"/>
        </port>
    </ports>
</host>
</nmaprun>"""

def test_parser_rejects_malformed_xml():
    """SEC-012: Malformed XML must raise InvalidNmapXMLError without crashing the application."""
    for sample in MALFORMED_XML_SAMPLES:
        with pytest.raises(InvalidNmapXMLError):
            parse_nmap_xml(sample)


def test_parser_extracts_valid_nmap_data():
    """Verify that a standard Nmap XML document is correctly parsed into structured data."""
    parsed = parse_nmap_xml(VALID_NMAP_XML_SAMPLE)

    assert parsed['scanner'] == 'nmap'
    assert parsed['total_hosts'] == 1
    assert parsed['open_ports_count'] == 2

    host = parsed['hosts'][0]
    assert host['ip_address'] == '192.168.1.10'
    assert host['hostname'] == 'vuln-node.lab'
    assert host['state'] == 'up'
    assert 'Linux' in host['os_information']

    ports = host['ports']
    assert len(ports) == 3

    open_ports = [p for p in ports if p['state'] == 'open']
    assert len(open_ports) == 2

    ssh_port = next(p for p in ports if p['port_number'] == 22)
    assert ssh_port['service'] == 'ssh'
    assert ssh_port['product'] == 'OpenSSH'
    assert ssh_port['version'] == '8.2p1'

    http_port = next(p for p in ports if p['port_number'] == 80)
    assert http_port['service'] == 'http'
    assert http_port['product'] == 'Apache httpd'

    # Check script extraction
    scripts = host['scripts']
    assert len(scripts) >= 2
    script_ids = [s['script_id'] for s in scripts]
    assert 'ssh2-enum-algos' in script_ids
    assert 'http-title' in script_ids
