import os
import shutil
import tempfile
import pytest
from datetime import datetime
from app import create_app
from config import Config
from models import db, User, Scan, Host, Port, NSEResult, Finding, Report

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key-12345'
    ALLOW_PUBLIC_SCANS = False
    ALLOW_PRIVATE_SUBNETS = True
    ALLOW_LOCALHOST = True
    ALLOWED_LAB_TARGETS = ['127.0.0.1', 'localhost', '192.168.1.10', '192.168.1.20', '10.0.0.5']

class TestConfigWithCSRF(TestConfig):
    WTF_CSRF_ENABLED = True
    SECRET_KEY = 'test-secret-key-csrf'

@pytest.fixture
def app(tmp_path):
    # Set isolated temporary directories for scans and reports
    test_scans_dir = str(tmp_path / 'scans')
    test_reports_dir = str(tmp_path / 'reports')
    os.makedirs(test_scans_dir, exist_ok=True)
    os.makedirs(test_reports_dir, exist_ok=True)

    class DynamicTestConfig(TestConfig):
        SCANS_FOLDER = test_scans_dir
        REPORTS_FOLDER = test_reports_dir

    app = create_app(DynamicTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def auth_user(app):
    with app.app_context():
        user = User(username='testadmin', is_active=True)
        user.set_password('SecretPassword123!')
        db.session.add(user)
        db.session.commit()
        yield user

@pytest.fixture
def second_user(app):
    with app.app_context():
        user = User(username='attacker_or_other_user', is_active=True)
        user.set_password('OtherUserPass456!')
        db.session.add(user)
        db.session.commit()
        yield user

@pytest.fixture
def authenticated_client(app, auth_user):
    c = app.test_client()
    c.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })
    return c

@pytest.fixture
def authenticated_client_user2(app, second_user):
    c = app.test_client()
    c.post('/login', data={
        'username': 'attacker_or_other_user',
        'password': 'OtherUserPass456!'
    })
    return c

@pytest.fixture
def sample_completed_scan(app, auth_user):
    """Creates a rich, completed scan owned by user 1 with hosts, ports, NSE, and findings."""
    with app.app_context():
        scan = Scan(
            user_id=auth_user.id,
            target='192.168.1.10',
            scan_profile='service_default_nse',
            status='completed',
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            duration=4.52,
            number_of_hosts=1,
            number_of_open_ports=2,
            number_of_findings=2
        )
        db.session.add(scan)
        db.session.commit()

        # Create dummy XML file in scans dir
        scan_dir = os.path.join(app.config['SCANS_FOLDER'], str(scan.id))
        os.makedirs(scan_dir, exist_ok=True)
        xml_file = os.path.join(scan_dir, 'result.xml')
        with open(xml_file, 'w', encoding='utf-8') as f:
            f.write("""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -sV 192.168.1.10">
<host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="test-lab.local"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4.41"/></port>
</ports></host></nmaprun>""")
        scan.xml_path = xml_file

        # Add Host
        host = Host(
            scan_id=scan.id,
            ip_address='192.168.1.10',
            hostname='test-lab.local',
            state='up',
            os_information='Ubuntu Linux 20.04'
        )
        db.session.add(host)
        db.session.flush()

        # Add Ports
        p1 = Port(
            host_id=host.id,
            port_number=22,
            protocol='tcp',
            state='open',
            service='ssh',
            product='OpenSSH',
            version='8.2p1'
        )
        p2 = Port(
            host_id=host.id,
            port_number=80,
            protocol='tcp',
            state='open',
            service='http',
            product='Apache',
            version='2.4.41'
        )
        db.session.add_all([p1, p2])
        db.session.flush()

        # Add NSE Results
        nse = NSEResult(
            scan_id=scan.id,
            host_id=host.id,
            script_id='http-title',
            service='http',
            port_number=80,
            output='Site: Test Lab Dashboard',
            status='Completed'
        )
        db.session.add(nse)

        # Add Findings
        f1 = Finding(
            scan_id=scan.id,
            host_id=host.id,
            port_id=p2.id,
            rule_id='NMAP-HTTP-001',
            category='Cleartext Protocol',
            title='Cleartext HTTP Protocol Detected',
            severity='MEDIUM',
            description='Web server listening on port 80 without SSL/TLS encryption.',
            evidence='Port 80/tcp open (http)',
            remediation='Implement HTTPS with TLS certificates.',
            confidence='HIGH',
            observation_type='POTENTIAL',
            status='OPEN'
        )
        f2 = Finding(
            scan_id=scan.id,
            host_id=host.id,
            port_id=p1.id,
            rule_id='NMAP-OBS-001',
            category='Service Observation',
            title='Open SSH Service Detected',
            severity='INFO',
            description='SSH administrative service is actively listening.',
            evidence='Port 22/tcp open (ssh)',
            remediation='Ensure strong key-based authentication and restrict access.',
            confidence='HIGH',
            observation_type='OBSERVED',
            status='OPEN'
        )
        db.session.add_all([f1, f2])
        db.session.commit()
        scan_id = scan.id

    return scan_id

@pytest.fixture
def sample_user2_scan(app, second_user):
    """Creates a scan belonging strictly to User 2."""
    with app.app_context():
        scan = Scan(
            user_id=second_user.id,
            target='192.168.1.20',
            scan_profile='basic_port_scan',
            status='completed',
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            duration=3.10,
            number_of_hosts=1,
            number_of_open_ports=1,
            number_of_findings=1
        )
        db.session.add(scan)
        db.session.commit()

        # Dummy XML
        scan_dir = os.path.join(app.config['SCANS_FOLDER'], str(scan.id))
        os.makedirs(scan_dir, exist_ok=True)
        xml_file = os.path.join(scan_dir, 'result.xml')
        with open(xml_file, 'w', encoding='utf-8') as f:
            f.write("""<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" version="7.94" args="nmap 192.168.1.20"><host><status state="up"/><address addr="192.168.1.20"/></host></nmaprun>""")
        scan.xml_path = xml_file

        host = Host(scan_id=scan.id, ip_address='192.168.1.20', state='up')
        db.session.add(host)
        db.session.flush()

        port = Port(host_id=host.id, port_number=443, protocol='tcp', state='open', service='https')
        db.session.add(port)
        db.session.flush()

        f = Finding(
            scan_id=scan.id,
            host_id=host.id,
            port_id=port.id,
            rule_id='NMAP-OBS-001',
            title='HTTPS Service Detected',
            severity='INFO',
            description='HTTPS detected on user 2 target.',
            status='OPEN'
        )
        db.session.add(f)
        db.session.commit()
        s_id = scan.id

    return s_id
