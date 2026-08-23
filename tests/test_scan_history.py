"""
Phase 10 — Scan History & Detailed Results Engine Tests
=========================================================
Tests cover: history page, search, filtering, sorting, pagination,
scan details, host/port/NSE/finding associations, authorization (IDOR),
deletion, rescan, XML access, and security.
"""
import os
import pytest
from datetime import datetime, timedelta
from app import create_app
from config import Config
from models import db as _db, User, Scan, Host, Port, NSEResult, Finding


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-phase10-key'
    SCANS_FOLDER = os.path.join(os.path.dirname(__file__), 'fixtures')


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user_a(app):
    """Primary test user."""
    with app.app_context():
        u = User(username='alice', is_active=True)
        u.set_password('AlicePass123!')
        _db.session.add(u)
        _db.session.commit()
        yield u


@pytest.fixture
def user_b(app):
    """Secondary test user for IDOR tests."""
    with app.app_context():
        u = User(username='bob', is_active=True)
        u.set_password('BobPass123!')
        _db.session.add(u)
        _db.session.commit()
        yield u


@pytest.fixture
def auth_client_a(client, user_a):
    """Authenticated client for user_a."""
    client.post('/login', data={'username': 'alice', 'password': 'AlicePass123!'})
    return client


@pytest.fixture
def auth_client_b(client, user_b):
    """Authenticated client for user_b."""
    client.post('/login', data={'username': 'bob', 'password': 'BobPass123!'})
    return client


def _create_scan(user_id, target='192.168.1.10', profile='service_default_nse',
                 status='completed', duration=14.5, num_hosts=1, num_ports=3,
                 num_findings=2, start_offset_hours=0):
    """Helper to create a scan with associated records."""
    start = datetime.utcnow() - timedelta(hours=start_offset_hours)
    end = start + timedelta(seconds=duration) if duration else None

    scan = Scan(
        user_id=user_id,
        target=target,
        scan_profile=profile,
        status=status,
        start_time=start,
        end_time=end,
        duration=duration,
        number_of_hosts=num_hosts,
        number_of_open_ports=num_ports,
        number_of_findings=num_findings
    )
    _db.session.add(scan)
    _db.session.flush()

    # Create host
    host = Host(scan_id=scan.id, ip_address=target, hostname='test-host.local', state='up', os_information='Linux')
    _db.session.add(host)
    _db.session.flush()

    # Create ports
    for i, (port_num, svc) in enumerate([(22, 'ssh'), (80, 'http'), (443, 'https')]):
        if i >= num_ports:
            break
        port = Port(host_id=host.id, port_number=port_num, protocol='tcp', state='open',
                    service=svc, product=f'Test{svc.upper()}', version='1.0')
        _db.session.add(port)
        _db.session.flush()

        # Create finding on first port
        if i == 0 and num_findings > 0:
            for fi in range(num_findings):
                finding = Finding(
                    scan_id=scan.id, host_id=host.id, port_id=port.id,
                    rule_id=f'RULE-{fi+1}', category='test-category',
                    title=f'Test Finding {fi+1}', severity='high' if fi == 0 else 'medium',
                    description=f'Test description {fi+1}', evidence=f'Test evidence {fi+1}',
                    recommendation='Test recommendation', remediation='Test remediation',
                    confidence='HIGH', observation_type='OBSERVED', status='OPEN'
                )
                _db.session.add(finding)

    # Create NSE result
    nse = NSEResult(
        scan_id=scan.id, host_id=host.id, script_id='http-title',
        service='http', output='Test Page Title', severity='info',
        status='Completed', port_number=80
    )
    _db.session.add(nse)

    _db.session.commit()
    return scan


# =====================================================================
#  AUTHENTICATION TESTS
# =====================================================================

class TestAuthentication:
    """Verify unauthenticated users cannot access scan pages."""

    def test_history_requires_login(self, client):
        resp = client.get('/scan/history')
        assert resp.status_code in (302, 401)

    def test_scan_results_requires_login(self, client):
        resp = client.get('/scan/results/1')
        assert resp.status_code in (302, 401)

    def test_api_scans_requires_login(self, client):
        resp = client.get('/api/scans/1')
        assert resp.status_code in (302, 401)

    def test_api_delete_requires_login(self, client):
        resp = client.delete('/api/scans/1')
        assert resp.status_code in (302, 401)

    def test_api_hosts_requires_login(self, client):
        resp = client.get('/api/scans/1/hosts')
        assert resp.status_code in (302, 401)


# =====================================================================
#  SCAN HISTORY PAGE TESTS
# =====================================================================

class TestScanHistory:
    """Scan History page functionality."""

    def test_history_page_loads(self, auth_client_a):
        resp = auth_client_a.get('/scan/history')
        assert resp.status_code == 200
        assert b'Scan History' in resp.data or b'Scan Archives' in resp.data

    def test_history_shows_real_scans(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.1')
        resp = auth_client_a.get('/scan/history')
        assert resp.status_code == 200
        assert b'10.0.0.1' in resp.data

    def test_history_empty_state(self, auth_client_a):
        resp = auth_client_a.get('/scan/history')
        assert resp.status_code == 200
        assert b'No scan history yet' in resp.data or b'No scans found' in resp.data

    def test_history_does_not_show_other_users_scans(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            _create_scan(user_b.id, target='10.99.99.99')
        resp = auth_client_a.get('/scan/history')
        assert b'10.99.99.99' not in resp.data

    def test_history_alias_redirects(self, auth_client_a):
        resp = auth_client_a.get('/history')
        assert resp.status_code in (301, 302, 308)


# =====================================================================
#  SEARCH TESTS
# =====================================================================

class TestSearch:
    """Search functionality on scan history."""

    def test_search_by_target(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='172.16.0.1')
            _create_scan(user_a.id, target='192.168.1.1')
        resp = auth_client_a.get('/scan/history?q=172.16')
        assert resp.status_code == 200
        assert b'172.16.0.1' in resp.data
        assert b'192.168.1.1' not in resp.data

    def test_search_by_scan_id(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='10.0.0.5')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/history?q={scan_id}')
        assert resp.status_code == 200
        assert b'10.0.0.5' in resp.data

    def test_search_no_results(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.1')
        resp = auth_client_a.get('/scan/history?q=nonexistent')
        assert resp.status_code == 200
        assert b'No scans match' in resp.data or b'No scans found' in resp.data


# =====================================================================
#  FILTER TESTS
# =====================================================================

class TestFiltering:
    """Filtering functionality on scan history."""

    def test_filter_by_status(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.1', status='completed')
            _create_scan(user_a.id, target='10.0.0.2', status='failed')
        resp = auth_client_a.get('/scan/history?status=completed')
        assert resp.status_code == 200
        assert b'10.0.0.1' in resp.data
        assert b'10.0.0.2' not in resp.data

    def test_filter_by_profile(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.1', profile='basic_port_scan')
            _create_scan(user_a.id, target='10.0.0.2', profile='service_default_nse')
        resp = auth_client_a.get('/scan/history?profile=basic_port_scan')
        assert resp.status_code == 200
        assert b'10.0.0.1' in resp.data
        assert b'10.0.0.2' not in resp.data

    def test_combined_filters(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.1', status='completed', profile='basic_port_scan')
            _create_scan(user_a.id, target='10.0.0.2', status='completed', profile='service_default_nse')
            _create_scan(user_a.id, target='10.0.0.3', status='failed', profile='basic_port_scan')
        resp = auth_client_a.get('/scan/history?status=completed&profile=basic_port_scan')
        assert resp.status_code == 200
        assert b'10.0.0.1' in resp.data
        assert b'10.0.0.2' not in resp.data
        assert b'10.0.0.3' not in resp.data


# =====================================================================
#  SORTING TESTS
# =====================================================================

class TestSorting:
    """Sorting functionality on scan history."""

    def test_sort_newest(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.OLD', start_offset_hours=48)
            _create_scan(user_a.id, target='10.0.0.NEW', start_offset_hours=1)
        resp = auth_client_a.get('/scan/history?sort=newest')
        assert resp.status_code == 200
        data = resp.data.decode()
        assert data.index('10.0.0.NEW') < data.index('10.0.0.OLD')

    def test_sort_oldest(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.OLD', start_offset_hours=48)
            _create_scan(user_a.id, target='10.0.0.NEW', start_offset_hours=1)
        resp = auth_client_a.get('/scan/history?sort=oldest')
        assert resp.status_code == 200
        data = resp.data.decode()
        assert data.index('10.0.0.OLD') < data.index('10.0.0.NEW')


# =====================================================================
#  PAGINATION TESTS
# =====================================================================

class TestPagination:
    """Pagination functionality."""

    def test_pagination_first_page(self, app, auth_client_a, user_a):
        with app.app_context():
            for i in range(25):
                _create_scan(user_a.id, target=f'10.0.0.{i+1}', start_offset_hours=i)
        resp = auth_client_a.get('/scan/history?per_page=10')
        assert resp.status_code == 200
        # Should show pagination controls
        assert b'Next' in resp.data

    def test_pagination_second_page(self, app, auth_client_a, user_a):
        with app.app_context():
            for i in range(25):
                _create_scan(user_a.id, target=f'10.0.0.{i+1}', start_offset_hours=i)
        resp = auth_client_a.get('/scan/history?page=2&per_page=10')
        assert resp.status_code == 200
        assert b'Previous' in resp.data


# =====================================================================
#  SCAN DETAIL PAGE TESTS
# =====================================================================

class TestScanDetails:
    """Scan detail page tests."""

    def test_scan_results_page_loads(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.56.20')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert resp.status_code == 200
        assert b'192.168.56.20' in resp.data

    def test_scan_results_shows_hosts(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.56.20')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert resp.status_code == 200
        assert b'test-host.local' in resp.data

    def test_scan_results_shows_findings(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.56.20', num_findings=3)
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert resp.status_code == 200
        assert b'Test Finding 1' in resp.data

    def test_scan_results_404_nonexistent(self, auth_client_a):
        resp = auth_client_a.get('/scan/results/99999')
        assert resp.status_code == 404

    def test_scan_results_shows_nse(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.56.20')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert resp.status_code == 200
        assert b'http-title' in resp.data

    def test_failed_scan_display(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='10.0.0.1', status='failed',
                                duration=None, num_hosts=0, num_ports=0, num_findings=0)
            scan.error_message = 'Connection timed out'
            _db.session.commit()
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert resp.status_code == 200
        assert b'FAILED' in resp.data or b'Failed' in resp.data

    def test_back_to_history_link(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='10.0.0.1')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert resp.status_code == 200
        assert b'Back to Scan History' in resp.data


# =====================================================================
#  AUTHORIZATION / IDOR TESTS
# =====================================================================

class TestAuthorization:
    """IDOR and authorization tests."""

    def test_cannot_view_other_users_scan(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert resp.status_code == 404

    def test_cannot_view_other_users_scan_api(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}')
        assert resp.status_code in (403, 404)

    def test_cannot_delete_other_users_scan(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan_id = scan.id
        resp = auth_client_a.delete(f'/api/scans/{scan_id}')
        assert resp.status_code in (403, 404)

    def test_cannot_access_other_users_hosts_api(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/hosts')
        assert resp.status_code in (403, 404)

    def test_cannot_access_other_users_findings_api(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/findings')
        assert resp.status_code in (403, 404)

    def test_cannot_access_other_users_nse_api(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/nse')
        assert resp.status_code in (403, 404)

    def test_cannot_access_other_users_xml(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan.xml_path = 'fake/path.xml'
            _db.session.commit()
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/raw-xml/{scan_id}')
        assert resp.status_code in (403, 404)

    def test_scan_progress_404_other_user(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99', status='running')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/progress/{scan_id}')
        assert resp.status_code in (403, 404)


# =====================================================================
#  API ENDPOINT TESTS
# =====================================================================

class TestScanAPIs:
    """Scan-scoped API endpoint tests."""

    def test_api_scan_detail(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['target'] == '192.168.1.10'
        assert 'hosts' in data

    def test_api_scan_hosts(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/hosts')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 1
        assert data[0]['ip_address'] == '192.168.1.10'

    def test_api_scan_ports(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/ports')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 1

    def test_api_scan_ports_filter_open(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/ports?state=open')
        assert resp.status_code == 200
        data = resp.get_json()
        for p in data:
            assert p['state'].lower() == 'open'

    def test_api_scan_services(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/services')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 1

    def test_api_scan_nse(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/nse')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 1
        assert data[0]['script_id'] == 'http-title'

    def test_api_scan_findings(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10', num_findings=3)
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/findings')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 3

    def test_api_scan_findings_filter_severity(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10', num_findings=3)
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/findings?severity=high')
        assert resp.status_code == 200
        data = resp.get_json()
        for f in data:
            assert f['severity'].lower() == 'high'

    def test_api_finding_detail(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='192.168.1.10', num_findings=1)
            scan_id = scan.id
            finding = Finding.query.filter_by(scan_id=scan_id).first()
            finding_id = finding.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/findings/{finding_id}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['title'] == 'Test Finding 1'
        assert data['rule_id'] == 'RULE-1'
        assert 'description' in data
        assert 'evidence' in data
        assert 'remediation' in data

    def test_api_finding_detail_wrong_scan(self, app, auth_client_a, user_a):
        """Finding from one scan cannot be accessed via another scan ID."""
        with app.app_context():
            scan1 = _create_scan(user_a.id, target='10.0.0.1', num_findings=1)
            scan2 = _create_scan(user_a.id, target='10.0.0.2', num_findings=0)
            finding = Finding.query.filter_by(scan_id=scan1.id).first()
            scan2_id = scan2.id
            finding_id = finding.id
        resp = auth_client_a.get(f'/api/scans/{scan2_id}/findings/{finding_id}')
        assert resp.status_code == 404

    def test_api_scan_status(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='10.0.0.1')
            scan_id = scan.id
        resp = auth_client_a.get(f'/api/scans/{scan_id}/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'completed'

    def test_api_get_scans_list(self, app, auth_client_a, user_a):
        with app.app_context():
            _create_scan(user_a.id, target='10.0.0.1', status='completed')
            _create_scan(user_a.id, target='10.0.0.2', status='failed')
        resp = auth_client_a.get('/api/scans')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'scans' in data
        assert data['total'] >= 2
        assert len(data['scans']) >= 2

    def test_scans_alias_route(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='10.0.0.1')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scans/{scan_id}')
        assert resp.status_code == 200
        assert b'10.0.0.1' in resp.data


# =====================================================================
#  DELETE TESTS
# =====================================================================

class TestScanDeletion:
    """Scan deletion tests."""

    def test_delete_own_scan(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='10.0.0.1')
            scan_id = scan.id
        resp = auth_client_a.delete(f'/api/scans/{scan_id}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

        # Verify scan is gone
        with app.app_context():
            assert _db.session.get(Scan, scan_id) is None

    def test_delete_cascades(self, app, auth_client_a, user_a):
        """Deletion must remove hosts, ports, NSE, findings."""
        with app.app_context():
            scan = _create_scan(user_a.id, target='10.0.0.1', num_findings=2)
            scan_id = scan.id
            host_count_before = Host.query.filter_by(scan_id=scan_id).count()
            assert host_count_before > 0

        auth_client_a.delete(f'/api/scans/{scan_id}')

        with app.app_context():
            assert Host.query.filter_by(scan_id=scan_id).count() == 0
            assert Finding.query.filter_by(scan_id=scan_id).count() == 0
            assert NSEResult.query.filter_by(scan_id=scan_id).count() == 0

    def test_delete_nonexistent(self, auth_client_a):
        resp = auth_client_a.delete('/api/scans/99999')
        assert resp.status_code == 404

    def test_delete_other_users_scan_blocked(self, app, auth_client_a, user_a, user_b):
        with app.app_context():
            scan = _create_scan(user_b.id, target='10.99.99.99')
            scan_id = scan.id
        resp = auth_client_a.delete(f'/api/scans/{scan_id}')
        assert resp.status_code in (403, 404)
        # Verify scan still exists
        with app.app_context():
            assert _db.session.get(Scan, scan_id) is not None


# =====================================================================
#  DATA CONSISTENCY TESTS
# =====================================================================

class TestDataConsistency:
    """Cross-scan contamination tests."""

    def test_no_cross_scan_hosts(self, app, auth_client_a, user_a):
        """Scan A's hosts must not appear in Scan B's results."""
        with app.app_context():
            scan_a = _create_scan(user_a.id, target='10.0.0.1')
            scan_b = _create_scan(user_a.id, target='10.0.0.2')
            scan_b_id = scan_b.id

        resp = auth_client_a.get(f'/api/scans/{scan_b_id}/hosts')
        data = resp.get_json()
        for h in data:
            assert h['ip_address'] != '10.0.0.1'

    def test_no_cross_scan_findings(self, app, auth_client_a, user_a):
        with app.app_context():
            scan_a = _create_scan(user_a.id, target='10.0.0.1', num_findings=2)
            scan_b = _create_scan(user_a.id, target='10.0.0.2', num_findings=1)
            scan_a_id = scan_a.id
            scan_b_id = scan_b.id

        resp_a = auth_client_a.get(f'/api/scans/{scan_a_id}/findings')
        resp_b = auth_client_a.get(f'/api/scans/{scan_b_id}/findings')
        data_a = resp_a.get_json()
        data_b = resp_b.get_json()
        assert len(data_a) == 2
        assert len(data_b) == 1

    def test_no_cross_scan_nse(self, app, auth_client_a, user_a):
        with app.app_context():
            scan_a = _create_scan(user_a.id, target='10.0.0.1')
            scan_b = _create_scan(user_a.id, target='10.0.0.2')
            scan_a_id = scan_a.id
            scan_b_id = scan_b.id

        resp_a = auth_client_a.get(f'/api/scans/{scan_a_id}/nse')
        resp_b = auth_client_a.get(f'/api/scans/{scan_b_id}/nse')
        # Each scan has its own NSE results
        data_a = resp_a.get_json()
        data_b = resp_b.get_json()
        a_ids = {r['id'] for r in data_a}
        b_ids = {r['id'] for r in data_b}
        assert a_ids.isdisjoint(b_ids)


# =====================================================================
#  XSS PREVENTION TESTS
# =====================================================================

class TestXSSPrevention:
    """Test that malicious input is properly escaped."""

    def test_xss_in_target(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='<script>alert(1)</script>')
            scan_id = scan.id
        resp = auth_client_a.get('/scan/history')
        assert b'<script>alert(1)</script>' not in resp.data
        # Jinja2 auto-escapes, so we should see the escaped version
        assert b'&lt;script&gt;' in resp.data

    def test_xss_in_scan_results(self, app, auth_client_a, user_a):
        with app.app_context():
            scan = _create_scan(user_a.id, target='<img src=x onerror=alert(1)>')
            scan_id = scan.id
        resp = auth_client_a.get(f'/scan/results/{scan_id}')
        assert b'<img src=x onerror=alert(1)>' not in resp.data


# =====================================================================
#  SQL INJECTION PREVENTION TESTS
# =====================================================================

class TestSQLInjection:
    """Test that search/filter params don't allow SQL injection."""

    def test_sqli_in_search(self, app, auth_client_a, user_a):
        resp = auth_client_a.get("/scan/history?q=' OR 1=1 --")
        assert resp.status_code == 200

    def test_sqli_in_status_filter(self, app, auth_client_a, user_a):
        resp = auth_client_a.get("/scan/history?status=' OR 1=1 --")
        assert resp.status_code == 200

    def test_sqli_in_profile_filter(self, app, auth_client_a, user_a):
        resp = auth_client_a.get("/scan/history?profile=' OR 1=1 --")
        assert resp.status_code == 200
