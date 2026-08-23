import pytest
from flask import url_for
from models import db, Scan, Host, Port, NSEResult, User
from services.service_enumerator import get_service_category, enumerate_services, get_service_counts
from services.nse_service import NSE_PROFILES, NSE_SCRIPTS_LIBRARY, execute_nse_scripts_for_scan

def test_get_service_category():
    # Test service name mappings
    assert get_service_category("http", 80) == "HTTP"
    assert get_service_category("https", 443) == "HTTPS"
    assert get_service_category("ssl/http", 443) == "HTTPS"
    assert get_service_category("ssh", 22) == "SSH"
    assert get_service_category("domain", 53) == "DNS"
    assert get_service_category("mysql", 3306) == "MySQL"
    assert get_service_category("postgresql", 5432) == "PostgreSQL"
    
    # Test fallback by port if service name is empty
    assert get_service_category("", 80) == "HTTP"
    assert get_service_category("", 22) == "SSH"
    assert get_service_category(None, 3306) == "MySQL"
    assert get_service_category("unknown-custom-service", 9999) == "Other"

def test_service_enumeration_and_counts(app, auth_user):
    with app.app_context():
        # Setup mock scan owned by user
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()

        port1 = Port(host_id=host.id, port_number=80, protocol="tcp", state="open", service="http", product="Apache", version="2.4")
        port2 = Port(host_id=host.id, port_number=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="8.2")
        db.session.add_all([port1, port2])
        db.session.commit()

        # Enumerate services
        services = enumerate_services(auth_user.id)
        assert len(services) == 2
        
        http_service = next(s for s in services if s['port'] == 80)
        assert http_service['category'] == 'HTTP'
        assert http_service['product'] == 'Apache'
        assert http_service['version'] == '2.4'

        ssh_service = next(s for s in services if s['port'] == 22)
        assert ssh_service['category'] == 'SSH'
        assert ssh_service['version'] == '8.2'

        # Get service counts
        counts = get_service_counts(auth_user.id)
        assert counts['HTTP'] == 1
        assert counts['SSH'] == 1
        assert counts['Other'] == 0

        # Test search query
        found = enumerate_services(auth_user.id, search_query="Apache")
        assert len(found) == 1
        assert found[0]['port'] == 80

        # Test filter
        filtered = enumerate_services(auth_user.id, filters={'service': 'ssh'})
        assert len(filtered) == 1
        assert filtered[0]['port'] == 22

def test_nse_script_selection_and_simulation(app, auth_user):
    with app.app_context():
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()

        port = Port(host_id=host.id, port_number=80, protocol="tcp", state="open", service="http", product="Apache")
        db.session.add(port)
        db.session.commit()

        # Run simulated NSE scripts (since Nmap won't be in test env path or will fall back)
        success = execute_nse_scripts_for_scan(scan.id, app)
        assert success is True

        results = NSEResult.query.filter_by(scan_id=scan.id).all()
        # Should contain http-title, http-headers (Completed) and ssh2-enum-algos (Skipped)
        assert len(results) == 3
        
        http_title = next(r for r in results if r.script_id == "http-title")
        assert http_title.status == "Completed"
        assert "Landing Page" in http_title.output
        assert http_title.port_number == 80

        ssh_algos = next(r for r in results if r.script_id == "ssh2-enum-algos")
        assert ssh_algos.status == "Skipped"
        assert ssh_algos.error_message == "Required service was not detected."

def test_api_access_control(app, auth_user, client):
    # Create another user and scan
    with app.app_context():
        other_user = User(username='otheradmin', is_active=True)
        other_user.set_password('SecretPassword123!')
        db.session.add(other_user)
        db.session.commit()

        other_scan = Scan(user_id=other_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(other_scan)
        db.session.commit()
        other_scan_id = other_scan.id

    # Authenticate as first user
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    # Try triggering NSE on other user's scan
    response = client.post(f'/api/scans/{other_scan_id}/nse', json={"run": True})
    assert response.status_code == 403

    # Try accessing scans detail
    response = client.get(f'/api/scans/{other_scan_id}')
    assert response.status_code == 403

def test_unauthenticated_api_rejection(client):
    # Access services API without login
    response = client.get('/api/services')
    assert response.status_code == 302 # Redirect to login
