import re
import pytest

def test_full_dashboard_flow(client, auth_user):
    # 1. Access login page
    res = client.get('/login')
    assert res.status_code == 200

    # 2. Login
    res_login = client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    }, follow_redirects=True)
    assert res_login.status_code == 200

    # 3. Access Dashboard
    res_dash = client.get('/')
    assert res_dash.status_code == 200
    html = res_dash.data.decode('utf-8')
    assert 'NMAP' in html
    assert 'Security Suite' in html
    assert 'Authorized Lab' in html
    assert 'Total Scans' in html
    assert 'Hosts Scanned' in html
    assert 'Open Ports' in html
    assert 'Services Detected' in html
    assert 'Security Findings' in html
    assert 'Success Rate' in html
    assert 'Findings by Severity' in html
    assert 'Open Ports by Service' in html
    assert 'Scan Activity' in html
    assert 'Recent Scans' in html
    assert 'Top Hosts by Findings' in html
    assert 'Scan Profiles Used' in html
    assert 'All Systems Operational' in html

    # 4. Access API
    res_api = client.get('/api/dashboard/stats')
    assert res_api.status_code == 200
    json_data = res_api.get_json()
    assert json_data['kpi']['total_scans'] == 0
    assert json_data['kpi']['hosts_scanned'] == 0
    assert json_data['kpi']['open_ports'] == 0
    assert json_data['kpi']['security_findings'] == 0
    assert json_data['findings_severity']['total'] == 0

    # 5. Access other pages
    assert client.get('/scan/new').status_code == 200
    assert client.get('/scan/history').status_code == 200
    assert client.get('/findings').status_code == 200
    assert client.get('/about').status_code == 200
