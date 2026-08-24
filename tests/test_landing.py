"""
tests/test_landing.py
======================
Unit and integration tests for the public ScanVix 3D Landing Page.
Verifies:
1. Public unauthenticated access returns 200 OK.
2. Contains key brand headings, 3D canvas, and interactive components.
3. Authenticated users see 'Launch ScanVix' CTA.
4. No private scan data or sensitive APIs are exposed.
"""

import pytest

def test_landing_page_unauthenticated(client):
    """Verify the public landing page loads for unauthenticated visitors without redirect."""
    resp = client.get('/')
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')

    # Brand and Headings
    assert 'ScanVix' in html
    assert 'See Your Network' in html
    assert 'Understand Your Security' in html

    # 3D Canvas and Interactive Elements
    assert 'id="scanvix3DCanvas"' in html
    assert 'win-terminal' in html
    assert 'nmap 192.168.1.10' in html
    assert 'win-syn' in html
    assert 'nmap -sS' in html

    # Sections
    assert 'WHAT IS NMAP?' in html
    assert 'SCANVIX WORKFLOW' in html
    assert 'UNDERSTAND THE PORT' in html
    assert 'GO BEYOND PORT SCANNING' in html
    assert 'SECURITY FINDINGS' in html
    assert 'Port Discovery' in html

    # CTA Link points to login when unauthenticated
    assert '/login' in html


def test_landing_page_authenticated(client, auth_user):
    """Verify the public landing page renders 'Launch ScanVix' pointing to /dashboard for logged-in users."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    resp = client.get('/')
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')

    # Brand and CTA
    assert 'ScanVix' in html
    assert '/dashboard' in html
    assert 'Launch ScanVix' in html


def test_landing_page_does_not_leak_private_data(client, sample_completed_scan):
    """Verify that the public landing page does NOT query or leak private database scan records."""
    resp = client.get('/')
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')

    # Ensure private scan target from DB fixture is NOT rendered on public landing
    # (The landing page uses static illustrative examples only)
    assert f'id="{sample_completed_scan}"' not in html
    assert '/scan/results/' not in html
