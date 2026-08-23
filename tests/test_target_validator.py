import pytest
import json
from services.target_validator import validate_target
from config import Config

def test_valid_ipv4_targets():
    """Verify valid loopback and private IPv4 targets are accepted and normalized."""
    # Loopback
    res1 = validate_target("127.0.0.1")
    assert res1['valid'] is True
    assert res1['authorized'] is True
    assert res1['type'] == 'LOOPBACK'
    assert res1['target'] == '127.0.0.1'

    # Private Subnet RFC 1918 Class C
    res2 = validate_target("192.168.56.20")
    assert res2['valid'] is True
    assert res2['authorized'] is True
    assert res2['type'] == 'PRIVATE'
    assert res2['target'] == '192.168.56.20'

    # Class A Private
    res3 = validate_target("10.0.0.5")
    assert res3['valid'] is True
    assert res3['authorized'] is True
    assert res3['type'] == 'PRIVATE'
    assert res3['target'] == '10.0.0.5'

    # Class B Private
    res4 = validate_target("172.16.0.10")
    assert res4['valid'] is True
    assert res4['authorized'] is True
    assert res4['type'] == 'PRIVATE'
    assert res4['target'] == '172.16.0.10'

    # Leading/trailing whitespace normalization
    res5 = validate_target("   192.168.1.10   ")
    assert res5['valid'] is True
    assert res5['target'] == '192.168.1.10'

def test_invalid_ipv4_targets():
    """Verify malformed IPv4 targets are cleanly rejected."""
    # Out of octet range
    res1 = validate_target("999.999.999.999")
    assert res1['valid'] is False
    assert res1['authorized'] is False

    # Incomplete octets
    res2 = validate_target("192.168.1")
    assert res2['valid'] is False

    # Single invalid number with dots
    res3 = validate_target("192.168.1.999")
    assert res3['valid'] is False

    # Extra octets
    res4 = validate_target("192.168.1.1.1")
    assert res4['valid'] is False


def test_valid_ipv6_targets():
    """Verify valid IPv6 loopback and private addresses."""
    res1 = validate_target("::1")
    assert res1['valid'] is True
    assert res1['authorized'] is True
    assert res1['type'] == 'LOOPBACK'
    assert res1['target'] == '::1'

    res2 = validate_target("fe80::1")
    assert res2['valid'] is True
    assert res2['type'] == 'PRIVATE'

def test_valid_hostnames():
    """Verify valid lab hostnames are normalized and accepted."""
    allowed = ['ubuntu-lab.local', 'lab-server.local', 'training-target.local', 'localhost']

    res1 = validate_target("ubuntu-lab.local", authorized_targets=allowed)
    assert res1['valid'] is True
    assert res1['authorized'] is True
    assert res1['type'] == 'HOSTNAME'
    assert res1['target'] == 'ubuntu-lab.local'

    # Case normalization
    res2 = validate_target("UBUNTU-LAB.LOCAL", authorized_targets=allowed)
    assert res2['valid'] is True
    assert res2['target'] == 'ubuntu-lab.local'

    res3 = validate_target("localhost")
    assert res3['valid'] is True
    assert res3['authorized'] is True
    assert res3['target'] == 'localhost'

def test_invalid_hostnames():
    """Verify malformed hostnames are rejected."""
    # Starts with hyphen
    assert validate_target("-invalid.local")['valid'] is False

    # Consecutive dots
    assert validate_target("host..local")['valid'] is False

    # Empty string
    assert validate_target("")['valid'] is False
    assert validate_target("   ")['valid'] is False
    assert validate_target(None)['valid'] is False

def test_command_injection_protection():
    """Verify all command injection attempts and shell metacharacters are rejected."""
    injection_payloads = [
        "192.168.56.20; whoami",
        "192.168.56.20;whoami",
        "192.168.56.20 && whoami",
        "192.168.56.20&&whoami",
        "192.168.56.20 | cat /etc/passwd",
        "192.168.56.20|whoami",
        "$(whoami)",
        "`whoami`",
        "192.168.56.20 -sV",
        "-sV",
        "--script vuln",
        "192.168.56.20 > output.txt",
        "192.168.56.20 < input.txt",
        "192.168.56.20\nwhoami",
        "192.168.56.20\rwhoami",
        "192.168.56.20\\whoami",
        "192.168.56.20 &"
    ]

    for payload in injection_payloads:
        res = validate_target(payload)
        assert res['valid'] is False, f"Failed to reject injection payload: {payload}"
        assert res['authorized'] is False
        assert "Invalid target format." in res['message'] or "Target format is invalid." in res['message']

def test_unauthorized_public_targets():
    """Verify public Internet IP addresses are rejected by boundary policy unless whitelisted."""
    # Public IP without whitelist
    res1 = validate_target("8.8.8.8", authorized_targets=['127.0.0.1'])
    assert res1['valid'] is True
    assert res1['authorized'] is False
    assert "Target requires explicit authorization." in res1['message']

    res2 = validate_target("1.1.1.1", authorized_targets=['127.0.0.1'])
    assert res2['valid'] is True
    assert res2['authorized'] is False

    res3 = validate_target("google.com", authorized_targets=['ubuntu-lab.local'])
    assert res3['valid'] is True
    assert res3['authorized'] is False

def test_configurable_allowlist():
    """Verify changing authorized_targets dynamically updates authorization decisions."""
    # 8.8.8.8 not in allowlist
    res_disallowed = validate_target("8.8.8.8", authorized_targets=["192.168.56.20"], allow_private_subnets=False)
    assert res_disallowed['authorized'] is False

    # 8.8.8.8 explicitly added to allowlist
    res_allowed = validate_target("8.8.8.8", authorized_targets=["8.8.8.8"], allow_private_subnets=False)
    assert res_allowed['valid'] is True
    assert res_allowed['authorized'] is True

def test_api_validate_target_authenticated(client, auth_user):
    """Verify POST /api/validate-target endpoint returns structured JSON for valid/invalid inputs."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    # Test 1: Valid authorized target
    resp1 = client.post('/api/validate-target', json={'target': '192.168.56.20'})
    assert resp1.status_code == 200
    data1 = resp1.get_json()
    assert data1['valid'] is True
    assert data1['authorized'] is True
    assert data1['type'] == 'PRIVATE'
    assert data1['target'] == '192.168.56.20'

    # Test 2: Unauthorized target
    resp2 = client.post('/api/validate-target', json={'target': '8.8.8.8'})
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2['valid'] is True
    assert data2['authorized'] is False

    # Test 3: Command injection payload
    resp3 = client.post('/api/validate-target', json={'target': '192.168.56.20; whoami'})
    assert resp3.status_code == 200
    data3 = resp3.get_json()
    assert data3['valid'] is False
    assert data3['authorized'] is False

    # Test 4: Form-encoded input
    resp4 = client.post('/api/validate-target', data={'target': '127.0.0.1'})
    assert resp4.status_code == 200
    data4 = resp4.get_json()
    assert data4['valid'] is True
    assert data4['authorized'] is True

def test_api_validate_target_unauthenticated(client):
    """Verify unauthenticated requests are redirected or rejected."""
    resp = client.post('/api/validate-target', json={'target': '127.0.0.1'})
    assert resp.status_code == 302
    assert '/login' in resp.location
