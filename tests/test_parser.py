import os
import pytest
from models import db, Scan, Host, Port, NSEResult, User
from services.parser import (
    validate_xml_file,
    parse_nmap_xml,
    store_parsed_scan_results,
    parse_and_store_scan,
    XMLSecurityError,
    InvalidNmapXMLError
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')

def get_fixture_path(filename: str) -> str:
    return os.path.join(FIXTURES_DIR, filename)

def test_validate_xml_file_success(tmp_path):
    safe_xml = tmp_path / "result.xml"
    safe_xml.write_text("<nmaprun></nmaprun>")
    canonical = validate_xml_file(str(safe_xml), allowed_base_dir=str(tmp_path))
    assert canonical == os.path.abspath(str(safe_xml))

def test_validate_xml_file_path_traversal(tmp_path):
    restricted_dir = tmp_path / "scans"
    restricted_dir.mkdir()
    outside_file = tmp_path / "etc_passwd.xml"
    outside_file.write_text("<nmaprun></nmaprun>")

    with pytest.raises(XMLSecurityError):
        validate_xml_file(str(outside_file), allowed_base_dir=str(restricted_dir))

def test_validate_xml_file_nonexistent(tmp_path):
    missing_file = tmp_path / "nonexistent.xml"
    with pytest.raises(XMLSecurityError):
        validate_xml_file(str(missing_file))

def test_parse_basic_scan_xml():
    xml_path = get_fixture_path('basic_scan.xml')
    result = parse_nmap_xml(xml_path)

    assert result['scanner'] == 'nmap'
    assert result['total_hosts'] == 1
    assert result['open_ports_count'] == 2

    host = result['hosts'][0]
    assert host['ip_address'] == '192.168.1.10'
    assert host['hostname'] == 'lab-host-1.local'
    assert host['state'] == 'up'
    assert len(host['ports']) == 4

    ports_by_id = {p['port_number']: p for p in host['ports']}
    assert ports_by_id[22]['state'] == 'open'
    assert ports_by_id[22]['service'] == 'ssh'
    assert ports_by_id[80]['state'] == 'open'
    assert ports_by_id[443]['state'] == 'closed'
    assert ports_by_id[8080]['state'] == 'filtered'

def test_parse_service_scan_xml():
    xml_path = get_fixture_path('service_scan.xml')
    result = parse_nmap_xml(xml_path)

    assert result['total_hosts'] == 1
    host = result['hosts'][0]
    assert host['ip_address'] == '192.168.56.20'
    assert host['hostname'] == 'ubuntu-target.local'
    assert 'Linux 5.4 - 5.15' in host['os_information']

    ports_by_id = {p['port_number']: p for p in host['ports']}
    assert ports_by_id[22]['product'] == 'OpenSSH'
    assert ports_by_id[22]['version'] == '8.2p1 Ubuntu 4ubuntu0.5'
    assert 'Ubuntu Linux' in ports_by_id[22]['extra_info']

    assert ports_by_id[80]['product'] == 'Apache httpd'
    assert ports_by_id[80]['version'] == '2.4.41'

    assert ports_by_id[3306]['product'] == 'MySQL'
    assert ports_by_id[3306]['version'] == '8.0.35'

def test_parse_multi_host_xml():
    xml_path = get_fixture_path('multi_host.xml')
    result = parse_nmap_xml(xml_path)

    assert result['total_hosts'] == 4
    hosts_by_ip = {h['ip_address']: h for h in result['hosts']}

    assert '192.168.1.1' in hosts_by_ip
    assert hosts_by_ip['192.168.1.1']['hostname'] == 'gateway.local'
    assert hosts_by_ip['192.168.1.1']['state'] == 'up'

    assert '192.168.1.99' in hosts_by_ip
    assert hosts_by_ip['192.168.1.99']['state'] == 'down'

    assert 'fe80::1' in hosts_by_ip
    assert hosts_by_ip['fe80::1']['state'] == 'up'

def test_parse_nse_results_xml():
    xml_path = get_fixture_path('nse_results.xml')
    result = parse_nmap_xml(xml_path)

    host = result['hosts'][0]
    scripts = host['scripts']
    assert len(scripts) >= 5

    script_ids = [s['script_id'] for s in scripts]
    assert 'ssh2-enum-algos' in script_ids
    assert 'http-title' in script_ids
    assert 'clock-skew' in script_ids

def test_parse_malformed_xml():
    xml_path = get_fixture_path('malformed.xml')
    with pytest.raises(InvalidNmapXMLError):
        parse_nmap_xml(xml_path)

def test_parse_non_nmap_xml():
    xml_path = get_fixture_path('non_nmap.xml')
    with pytest.raises(InvalidNmapXMLError):
        parse_nmap_xml(xml_path)

def test_store_parsed_scan_results_db(app, authenticated_client, auth_user):
    with app.app_context():
        user = auth_user
        scan = Scan(
            user_id=user.id,
            target='192.168.56.20',
            scan_profile='service_default_nse',
            status='running'
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

        xml_path = get_fixture_path('service_scan.xml')
        parsed = parse_nmap_xml(xml_path)
        updated_scan = store_parsed_scan_results(scan_id, parsed)

        assert updated_scan.status == 'completed'
        assert updated_scan.number_of_hosts == 1
        assert updated_scan.number_of_open_ports == 3

        hosts = Host.query.filter_by(scan_id=scan_id).all()
        assert len(hosts) == 1
        assert hosts[0].ip_address == '192.168.56.20'
        assert len(hosts[0].ports) == 3

def test_duplicate_parsing_prevention(app, authenticated_client, auth_user):
    with app.app_context():
        user = auth_user
        scan = Scan(
            user_id=user.id,
            target='192.168.56.20',
            scan_profile='service_default_nse',
            status='running'
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

        xml_path = get_fixture_path('service_scan.xml')
        parsed = parse_nmap_xml(xml_path)

        # Parse twice
        store_parsed_scan_results(scan_id, parsed)
        store_parsed_scan_results(scan_id, parsed)

        hosts = Host.query.filter_by(scan_id=scan_id).all()
        assert len(hosts) == 1, "Duplicate hosts were created upon reparsing."
        ports = Port.query.filter(Port.host_id == hosts[0].id).all()
        assert len(ports) == 3, "Duplicate ports were created upon reparsing."

def test_api_get_scan_details_and_access_control(app, authenticated_client, auth_user):
    with app.app_context():
        user = auth_user
        scan = Scan(
            user_id=user.id,
            target='192.168.1.10',
            scan_profile='service_default_nse',
            status='completed'
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

        parsed = parse_nmap_xml(get_fixture_path('basic_scan.xml'))
        store_parsed_scan_results(scan_id, parsed)

    # 1. Access as owner (authenticated_client)
    res = authenticated_client.get(f'/api/scans/{scan_id}')
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['id'] == scan_id
    assert json_data['target'] == '192.168.1.10'
    assert len(json_data['hosts']) == 1

    # 2. Access as another user (User B) -> 403 Forbidden
    with app.app_context():
        user_b = User(username='user_b', is_active=True)
        user_b.set_password('Password123!')
        db.session.add(user_b)
        db.session.commit()

    user_b_client = app.test_client()
    user_b_client.get('/logout')
    login_res = user_b_client.post('/login', data={'username': 'user_b', 'password': 'Password123!'})
    assert login_res.status_code == 302
    forbidden_res = user_b_client.get(f'/api/scans/{scan_id}')
    assert forbidden_res.status_code == 403

    # 3. Unauthenticated access -> blocked (302 redirect or 401/403 forbidden)
    unauth_client = app.test_client()
    unauth_client.get('/logout')
    unauth_res = unauth_client.get(f'/api/scans/{scan_id}')
    assert unauth_res.status_code in (302, 401, 403)
