import os
import time
import pytest
from unittest.mock import patch, MagicMock
from models import db, Scan, User
from services.scan_profiles import get_scan_profiles, get_profile_by_id, is_valid_profile
from services.nmap_service import (
    check_nmap_availability,
    start_scan_job,
    cancel_active_scan,
    is_scan_running,
    get_active_scans_count,
    _active_scans,
    _active_scans_lock,
    ScanConcurrencyError,
    ScanAuthorizationError,
    ScanProfileError
)

@pytest.fixture(autouse=True)
def reset_active_scans():
    """Ensure no leftover active scans interfere with tests."""
    with _active_scans_lock:
        _active_scans.clear()
    yield
    with _active_scans_lock:
        _active_scans.clear()

def test_scan_profiles_registry():
    """Verify all 7 required predefined profiles are properly registered."""
    profiles = get_scan_profiles()
    required_keys = [
        "host_discovery",
        "basic_port_scan",
        "service_enumeration",
        "service_default_nse",
        "http_enumeration",
        "ssh_enumeration",
        "comprehensive_lab_scan"
    ]

    for key in required_keys:
        assert key in profiles
        p = profiles[key]
        assert "name" in p
        assert "arguments" in p
        assert "description" in p
        assert isinstance(p['arguments'], list)
        # Verify no shell commands or raw strings
        assert not any(';' in arg or '|' in arg or '&' in arg for arg in p['arguments'])

    assert is_valid_profile("service_default_nse") is True
    assert is_valid_profile("custom_malicious_profile") is False
    assert get_profile_by_id("nonexistent") is None

def test_nmap_availability_detection():
    """Verify Nmap availability check returns structured dict without throwing exceptions."""
    result = check_nmap_availability('nmap')
    assert isinstance(result, dict)
    assert 'available' in result
    assert 'version' in result
    assert 'message' in result

def test_start_scan_unauthorized_target(app, auth_user):
    """Verify scan launch is blocked if target fails authorization."""
    with app.app_context():
        with pytest.raises(ScanAuthorizationError):
            start_scan_job(
                app=app,
                user_id=auth_user.id,
                target="8.8.8.8",
                profile_id="basic_port_scan"
            )

def test_start_scan_invalid_profile(app, auth_user):
    """Verify scan launch is blocked if profile is not predefined."""
    with app.app_context():
        with pytest.raises(ScanProfileError):
            start_scan_job(
                app=app,
                user_id=auth_user.id,
                target="127.0.0.1",
                profile_id="arbitrary_flags_profile"
            )

def test_scan_execution_lifecycle(app, auth_user):
    """Verify scan initializes, runs, and updates status to completed in database."""
    with app.app_context():
        scan, msg = start_scan_job(
            app=app,
            user_id=auth_user.id,
            target="127.0.0.1",
            profile_id="host_discovery"
        )
        assert scan.id is not None
        assert scan.status in ('running', 'completed')
        assert scan.target == "127.0.0.1"
        assert scan.scan_profile == "host_discovery"

        # Wait briefly for background thread to complete
        time.sleep(4.5)

        updated_scan = db.session.get(Scan, scan.id)
        assert updated_scan.status == 'completed'
        assert updated_scan.duration is not None
        assert updated_scan.duration > 0
        assert updated_scan.xml_path is not None
        assert os.path.exists(updated_scan.xml_path)

def test_api_scan_profiles_endpoint(client, auth_user):
    """Verify GET /api/scan-profiles returns the JSON profiles catalog."""
    client.post('/login', data={'username': 'testadmin', 'password': 'SecretPassword123!'})
    resp = client.get('/api/scan-profiles')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'basic_port_scan' in data
    assert 'service_default_nse' in data

def test_api_start_scan_endpoint(client, auth_user):
    """Verify POST /api/scans endpoint creates scan and returns redirect."""
    client.post('/login', data={'username': 'testadmin', 'password': 'SecretPassword123!'})

    # Valid scan launch
    resp = client.post('/api/scans', json={
        'target': '192.168.56.20',
        'profile': 'basic_port_scan'
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data['success'] is True
    assert 'scan_id' in data
    scan_id = data['scan_id']

    # Check status endpoint
    status_resp = client.get(f'/api/scans/{scan_id}/status')
    assert status_resp.status_code == 200
    s_data = status_resp.get_json()
    assert s_data['id'] == scan_id
    assert s_data['target'] == '192.168.56.20'
    assert s_data['status'] in ('running', 'completed')

def test_api_start_scan_unauthorized(client, auth_user):
    """Verify POST /api/scans rejects unauthorized targets."""
    client.post('/login', data={'username': 'testadmin', 'password': 'SecretPassword123!'})

    resp = client.post('/api/scans', json={
        'target': '8.8.8.8',
        'profile': 'basic_port_scan'
    })
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False

def test_api_cancel_scan(client, auth_user):
    """Verify POST /api/scans/<id>/cancel cancels scan."""
    client.post('/login', data={'username': 'testadmin', 'password': 'SecretPassword123!'})

    resp = client.post('/api/scans', json={
        'target': '127.0.0.1',
        'profile': 'comprehensive_lab_scan'
    })
    data = resp.get_json()
    assert resp.status_code == 201
    scan_id = data['scan_id']

    cancel_resp = client.post(f'/api/scans/{scan_id}/cancel')
    assert cancel_resp.status_code == 200
    assert cancel_resp.get_json()['success'] is True
