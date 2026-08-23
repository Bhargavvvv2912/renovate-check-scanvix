import json
from models import db, User, Scan, Host, Port, Finding

def test_dashboard_authenticated(client, auth_user):
    """Verify dashboard loads with all required KPI cards and sections."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    response = client.get('/')
    assert response.status_code == 200
    assert b'Total Scans' in response.data
    assert b'Hosts Scanned' in response.data
    assert b'Open Ports' in response.data
    assert b'Services Detected' in response.data
    assert b'Security Findings' in response.data
    assert b'Success Rate' in response.data
    assert b'Findings by Severity' in response.data
    assert b'Open Ports by Service' in response.data
    assert b'Scan Activity' in response.data
    assert b'Recent Scans' in response.data
    assert b'Top Hosts by Findings' in response.data
    assert b'Scan Profiles Used' in response.data
    assert b'NMAP' in response.data
    assert b'Authorized Lab' in response.data

def test_dashboard_api_stats(client, auth_user):
    """Verify the dashboard JSON stats API returns correct schema."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    response = client.get('/api/dashboard/stats?period=month')
    assert response.status_code == 200
    data = json.loads(response.data)

    assert 'kpi' in data
    assert 'total_scans' in data['kpi']
    assert 'hosts_scanned' in data['kpi']
    assert 'open_ports' in data['kpi']
    assert 'findings_severity' in data
    assert 'open_ports_by_service' in data
    assert 'scan_activity' in data
    assert 'recent_scans' in data
    assert 'top_hosts' in data
    assert 'scan_profiles' in data
    assert 'services_detected_list' in data

def test_dashboard_unauthenticated_redirect(client):
    """Verify unauthenticated user cannot access dashboard or API."""
    res_dash = client.get('/')
    assert res_dash.status_code == 302
    assert '/login' in res_dash.location

    res_api = client.get('/api/dashboard/stats')
    assert res_api.status_code == 302
    assert '/login' in res_api.location
