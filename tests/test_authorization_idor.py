"""
tests/test_authorization_idor.py
================================
Multi-tenant IDOR (Insecure Direct Object Reference) and ownership isolation tests.
Verifies that User A cannot view, modify, delete, download XML, view findings,
or download PDF reports belonging to User B.
"""

import pytest
from models import db, Scan, Finding, Report

def test_unauthenticated_requests_redirected(client, sample_completed_scan):
    """SEC-001: Unauthenticated requests to protected scan/report routes must be blocked."""
    protected_urls = [
        '/dashboard',
        '/scan/new',
        f'/scan/progress/{sample_completed_scan}',
        f'/scan/results/{sample_completed_scan}',
        '/scan/history',
        f'/scan/raw-xml/{sample_completed_scan}',
        f'/report/view/{sample_completed_scan}',
        f'/report/download/{sample_completed_scan}',
        '/reports',
        '/findings',
        '/hosts',
        '/services',
        '/settings'
    ]
    for url in protected_urls:
        resp = client.get(url)
        assert resp.status_code in (302, 401, 403), f"Unauthenticated access permitted to {url} (status: {resp.status_code})"


def test_user_can_access_own_scan_details(authenticated_client, sample_completed_scan):
    """Verify that User 1 can access their own scan results and details."""
    resp = authenticated_client.get(f'/scan/results/{sample_completed_scan}')
    assert resp.status_code == 200

    api_resp = authenticated_client.get(f'/api/scans/{sample_completed_scan}')
    assert api_resp.status_code == 200
    data = api_resp.get_json()
    assert data['target'] == '192.168.1.10'
    assert data['id'] == sample_completed_scan


def test_idor_scan_details_access_denied(authenticated_client_user2, sample_completed_scan):
    """SEC-002: User 2 must NOT be able to view User 1's scan results or API scan details."""
    # HTML results view
    resp = authenticated_client_user2.get(f'/scan/results/{sample_completed_scan}')
    assert resp.status_code == 404, "User 2 was able to view User 1's scan results page"

    # API scan details
    api_resp = authenticated_client_user2.get(f'/api/scans/{sample_completed_scan}')
    assert api_resp.status_code in (403, 404), "User 2 was able to fetch User 1's scan JSON"

    # API scan status
    status_resp = authenticated_client_user2.get(f'/api/scans/{sample_completed_scan}/status')
    assert status_resp.status_code in (403, 404), "User 2 was able to fetch User 1's scan telemetry"


def test_idor_scan_scoped_entities_access_denied(authenticated_client_user2, sample_completed_scan):
    """SEC-002: User 2 cannot access scan-scoped hosts, ports, services, NSE, or findings."""
    endpoints = [
        f'/api/scans/{sample_completed_scan}/hosts',
        f'/api/scans/{sample_completed_scan}/ports',
        f'/api/scans/{sample_completed_scan}/services',
        f'/api/scans/{sample_completed_scan}/nse',
        f'/api/scans/{sample_completed_scan}/findings'
    ]
    for ep in endpoints:
        resp = authenticated_client_user2.get(ep)
        assert resp.status_code in (403, 404), f"User 2 accessed User 1's scoped endpoint: {ep}"


def test_idor_xml_download_denied(authenticated_client_user2, sample_completed_scan):
    """SEC-003: User 2 must NOT be able to download or inspect User 1's raw XML scan output."""
    resp = authenticated_client_user2.get(f'/scan/raw-xml/{sample_completed_scan}?download=1')
    assert resp.status_code in (403, 404), "User 2 was able to download User 1's scan XML artifact"


def test_idor_report_download_denied(authenticated_client_user2, sample_completed_scan):
    """SEC-004: User 2 must NOT be able to download or view User 1's PDF security report."""
    # HTML preview
    view_resp = authenticated_client_user2.get(f'/report/view/{sample_completed_scan}')
    assert view_resp.status_code in (403, 404), "User 2 viewed User 1's report preview"

    # PDF Download stream
    dl_resp = authenticated_client_user2.get(f'/report/download/{sample_completed_scan}')
    assert dl_resp.status_code in (403, 404), "User 2 downloaded User 1's PDF report"

    # Report generate API
    gen_resp = authenticated_client_user2.post(f'/api/scans/{sample_completed_scan}/report')
    assert gen_resp.status_code in (403, 404), "User 2 triggered report generation on User 1's scan"


def test_idor_finding_status_update_denied(app, authenticated_client_user2, sample_completed_scan):
    """SEC-005: User 2 must NOT be able to update the remediation status of User 1's findings."""
    with app.app_context():
        finding = Finding.query.filter_by(scan_id=sample_completed_scan).first()
        assert finding is not None
        finding_id = finding.id

    resp = authenticated_client_user2.post(
        f'/api/findings/{finding_id}/status',
        json={'status': 'RESOLVED'}
    )
    assert resp.status_code in (403, 404), "User 2 modified User 1's finding status"


def test_idor_scan_deletion_denied(authenticated_client_user2, sample_completed_scan):
    """SEC-006: User 2 must NOT be able to delete User 1's scan."""
    resp = authenticated_client_user2.delete(f'/api/scans/{sample_completed_scan}')
    assert resp.status_code in (403, 404), "User 2 deleted User 1's scan"


def test_idor_rescan_trigger_denied(authenticated_client_user2, sample_completed_scan):
    """User 2 must NOT be able to trigger rescan from User 1's scan ID."""
    resp = authenticated_client_user2.post(f'/api/scans/{sample_completed_scan}/rescan')
    assert resp.status_code in (403, 404), "User 2 triggered rescan using User 1's scan"


def test_user_history_data_isolation(app, auth_user, second_user, sample_completed_scan, sample_user2_scan):
    """SEC-020: History and dashboard data must show ONLY the logged in user's scans."""
    c1 = app.test_client()
    c1.post('/login', data={'username': 'testadmin', 'password': 'SecretPassword123!'})
    resp1 = c1.get('/api/scans')
    assert resp1.status_code == 200
    scans1 = resp1.get_json()['scans']
    targets1 = [s['target'] for s in scans1]
    assert '192.168.1.10' in targets1
    assert '192.168.1.20' not in targets1

    c2 = app.test_client()
    c2.get('/logout')
    login_resp = c2.post('/login', data={'username': 'attacker_or_other_user', 'password': 'OtherUserPass456!'})
    assert login_resp.status_code == 302
    resp2 = c2.get('/api/scans')
    assert resp2.status_code == 200
    scans2 = resp2.get_json()['scans']
    targets2 = [s['target'] for s in scans2]
    assert '192.168.1.20' in targets2
    assert '192.168.1.10' not in targets2
