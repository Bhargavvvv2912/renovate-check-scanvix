import pytest
from flask import url_for
from models import db, Scan, Host, Port, NSEResult, Finding, User
from services.findings_analyzer import analyze_scan_results
from services.finding_rules import FINDING_RULES

def test_http_cleartext_and_version_observation(app, auth_user):
    with app.app_context():
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()

        port = Port(host_id=host.id, port_number=80, protocol="tcp", state="open", service="http", product="Apache httpd", version="2.4.41")
        db.session.add(port)
        db.session.commit()

        # Run findings analysis
        success = analyze_scan_results(scan.id, app)
        assert success is True

        findings = Finding.query.filter_by(scan_id=scan.id).all()
        # Should trigger: NMAP-OBS-001 (Service Exposure), NMAP-HTTP-001 (Cleartext), NMAP-VERSION-001 (Version banners)
        assert len(findings) == 3
        
        # Check rule details
        obs_rule = next(f for f in findings if f.rule_id == "NMAP-OBS-001")
        assert obs_rule.severity == "INFO"
        assert obs_rule.observation_type == "OBSERVED"
        assert obs_rule.confidence == "HIGH"

        http_rule = next(f for f in findings if f.rule_id == "NMAP-HTTP-001")
        assert http_rule.severity == "LOW"
        assert http_rule.observation_type == "POTENTIAL"
        assert http_rule.confidence == "MEDIUM"

        version_rule = next(f for f in findings if f.rule_id == "NMAP-VERSION-001")
        assert version_rule.severity == "INFO"
        assert version_rule.observation_type == "OBSERVED"
        assert "Apache httpd" in version_rule.evidence

def test_ftp_and_telnet_rules(app, auth_user):
    with app.app_context():
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()

        # Add FTP and Telnet ports
        port_ftp = Port(host_id=host.id, port_number=21, protocol="tcp", state="open", service="ftp")
        port_telnet = Port(host_id=host.id, port_number=23, protocol="tcp", state="open", service="telnet")
        db.session.add_all([port_ftp, port_telnet])
        db.session.commit()

        success = analyze_scan_results(scan.id, app)
        assert success is True

        findings = Finding.query.filter_by(scan_id=scan.id).all()
        
        # Check FTP cleartext
        ftp_f = next(f for f in findings if f.rule_id == "NMAP-FTP-001")
        assert ftp_f.severity == "LOW"
        assert ftp_f.observation_type == "POTENTIAL"

        # Check Telnet cleartext
        telnet_f = next(f for f in findings if f.rule_id == "NMAP-TELNET-001")
        assert telnet_f.severity == "MEDIUM"
        assert telnet_f.observation_type == "POTENTIAL"

def test_ssh_weak_kex_nse_rule(app, auth_user):
    with app.app_context():
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()

        port = Port(host_id=host.id, port_number=22, protocol="tcp", state="open", service="ssh")
        db.session.add(port)
        db.session.commit()

        # Add mock weak SSH2 enum algos result
        nse = NSEResult(
            scan_id=scan.id,
            host_id=host.id,
            port_number=22,
            script_id="ssh2-enum-algos",
            service="ssh",
            status="Completed",
            output="kex_algorithms: diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha1\nciphers: 3des-cbc, aes128-cbc"
        )
        db.session.add(nse)
        db.session.commit()

        success = analyze_scan_results(scan.id, app)
        assert success is True

        findings = Finding.query.filter_by(scan_id=scan.id).all()
        # Should trigger: NMAP-OBS-001 (Port open), NMAP-SSH-001 (SSH detected), NMAP-SSH-002 (Weak algos)
        assert len(findings) == 3

        ssh_weak = next(f for f in findings if f.rule_id == "NMAP-SSH-002")
        assert ssh_weak.severity == "LOW"
        assert ssh_weak.observation_type == "POTENTIAL"
        assert "3des-cbc" in ssh_weak.evidence

def test_database_and_rdp_rules(app, auth_user):
    with app.app_context():
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()

        port_db = Port(host_id=host.id, port_number=3306, protocol="tcp", state="open", service="mysql")
        port_rdp = Port(host_id=host.id, port_number=3389, protocol="tcp", state="open", service="ms-wbt-server")
        db.session.add_all([port_db, port_rdp])
        db.session.commit()

        success = analyze_scan_results(scan.id, app)
        assert success is True

        findings = Finding.query.filter_by(scan_id=scan.id).all()
        
        db_f = next(f for f in findings if f.rule_id == "NMAP-DB-001")
        assert db_f.severity == "LOW"
        assert db_f.observation_type == "OBSERVED"

        rdp_f = next(f for f in findings if f.rule_id == "NMAP-RDP-001")
        assert rdp_f.severity == "LOW"
        assert rdp_f.observation_type == "OBSERVED"

def test_false_positives_and_deduplication(app, auth_user):
    with app.app_context():
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()

        # HTTPS (443) should NOT trigger NMAP-HTTP-001 (cleartext)
        port_ssl = Port(host_id=host.id, port_number=443, protocol="tcp", state="open", service="https")
        db.session.add(port_ssl)
        db.session.commit()

        success = analyze_scan_results(scan.id, app)
        assert success is True

        findings = Finding.query.filter_by(scan_id=scan.id).all()
        # Should only trigger NMAP-OBS-001
        assert len(findings) == 1
        assert findings[0].rule_id == "NMAP-OBS-001"
        assert not any(f.rule_id == "NMAP-HTTP-001" for f in findings)

        # Run findings analyzer again - should NOT double create (deduplication check)
        success_again = analyze_scan_results(scan.id, app)
        assert success_again is True
        
        findings_after = Finding.query.filter_by(scan_id=scan.id).all()
        assert len(findings_after) == 1

def test_api_analyze_endpoints_and_access_control(app, auth_user, client):
    # Setup scan
    with app.app_context():
        scan = Scan(user_id=auth_user.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(scan)
        db.session.commit()
        host = Host(scan_id=scan.id, ip_address="127.0.0.1", state="up")
        db.session.add(host)
        db.session.commit()
        port = Port(host_id=host.id, port_number=80, protocol="tcp", state="open", service="http")
        db.session.add(port)
        db.session.commit()
        scan_id = scan.id

    client.post('/login', data={'username': 'testadmin', 'password': 'SecretPassword123!'})

    # Trigger scan analysis
    resp = client.post(f'/api/scans/{scan_id}/analyze')
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True

    # Check findings API GET
    resp_get = client.get('/api/findings')
    assert resp_get.status_code == 200
    assert len(resp_get.get_json()) > 0

    # Test other user access block
    with app.app_context():
        other = User(username="otheruser", is_active=True)
        other.set_password("SecretPassword123!")
        db.session.add(other)
        db.session.commit()
        
        other_scan = Scan(user_id=other.id, target="127.0.0.1", scan_profile="service_default_nse", status="completed")
        db.session.add(other_scan)
        db.session.commit()
        other_scan_id = other_scan.id

    resp_other = client.post(f'/api/scans/{other_scan_id}/analyze')
    assert resp_other.status_code == 403
