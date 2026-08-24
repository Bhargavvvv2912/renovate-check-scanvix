import pytest

def test_unauthenticated_route_protection(client):
    """Audit all application endpoints for unauthenticated redirect protection."""
    routes = [
        '/dashboard',
        '/scan/new',
        '/scan/progress/1',
        '/scan/results/1',
        '/scan/history',
        '/findings',
        '/reports',
        '/report/view/1',
        '/settings',
        '/about',
        '/api/dashboard/stats',
        '/hosts',
        '/services',
        '/nse-scripts',
        '/history'
    ]

    for r in routes:
        resp = client.get(r, follow_redirects=False)
        # Note: /history redirects to /scan/history (302), so it still redirects
        assert resp.status_code == 302, f"Route {r} was not protected (got {resp.status_code})"

def test_authenticated_route_rendering(client, auth_user, app):
    """Audit all registered routes when authenticated to ensure error-free rendering."""
    with app.app_context():
        from models import db, Scan
        scan = Scan(id=1, user_id=auth_user.id, target='127.0.0.1', scan_profile='service_default_nse', status='completed')
        db.session.add(scan)
        db.session.commit()

    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    get_routes = [
        ('/dashboard', b'NMAP', b'Dashboard'),
        ('/scan/new', b'Configure Target', b'Validate Target'),
        ('/scan/progress/1', b'Active Assessment Scanner', b'Execution'),
        ('/scan/results/1', b'Assessment Results Summary', b'Execution Metadata'),
        ('/scan/history', b'Scan Archives', b'Assessment History'),
        ('/findings', b'Identified Security Observations', b'High Severity'),
        ('/reports', b'Assessment History', b'Scan Archives'),
        ('/report/view/1', b'SECURITY ASSESSMENT REPORT', b'Executive Summary'),
        ('/settings', b'Laboratory Settings', b'Authorized Targets'),
        ('/about', b'Viva Cheat Sheet', b'Environment Diagnostics'),
        ('/hosts', b'Network Hosts Inventory', b'Discovered Network Targets'),
        ('/services', b'Network Service Inventory', b'Discovered Service Inventory'),
        ('/nse-scripts', b'Nmap Scripting Engine (NSE) Registry', b'Approved Scripts')
    ]


    for route, match1, match2 in get_routes:
        resp = client.get(route)
        assert resp.status_code == 200, f"Route {route} returned status {resp.status_code}"
        assert match1 in resp.data, f"Route {route} missing expected content: {match1}"
        assert match2 in resp.data, f"Route {route} missing expected content: {match2}"

def test_post_endpoints_audit(client, auth_user):
    """Audit all POST endpoints for correct handling and security."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    # Validate target API
    resp = client.post('/api/validate-target', json={'target': '192.168.56.20'})
    assert resp.status_code == 200
    assert resp.get_json()['authorized'] is True


def test_security_headers_present(client):
    """SEC-017: Verify presence of all required HTTP security hardening headers."""
    resp = client.get('/login')
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    assert resp.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert resp.headers.get('X-XSS-Protection') == '1; mode=block'
    assert resp.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'Content-Security-Policy' in resp.headers


def test_sidebar_and_exported_reports(client, auth_user):
    """Verify sidebar layout, toggle button accessibility, and exported reports page route."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    # Test that /exported-reports resolves successfully
    resp = client.get('/exported-reports')
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')

    # Check for sidebar elements and accessibility properties
    assert 'id="appSidebar"' in html
    assert 'aria-label="Toggle Sidebar Navigation"' in html
    assert 'title="Exported Reports"' in html
    assert 'title="Dashboard"' in html


