"""
tests/test_report_generator.py
==============================
ReportLab PDF Security Assessment Report Generator Tests.
Verifies end-to-end PDF generation, file creation, layout safety,
XML escaping, database persistence, and download authorization.
"""

import os
import pytest
from models import db, Scan, Host, Port, Finding, Report
from services.report_generator import generate_pdf_report, safe_escape, safe_code_text

def test_generate_pdf_report_success(app, sample_completed_scan):
    """Verify successful PDF report generation from real database entities."""
    with app.app_context():
        report_record, err = generate_pdf_report(sample_completed_scan, app=app)
        assert err is None, f"Report generation failed with error: {err}"
        assert report_record is not None
        assert report_record.status == 'COMPLETED'
        assert report_record.report_id.startswith('REP-')
        assert report_record.file_size > 0

        # Verify physical file existence
        full_path = os.path.join(app.root_path, report_record.file_path) if not os.path.isabs(report_record.file_path) else report_record.file_path
        assert os.path.exists(full_path), f"Report file not found at {full_path}"
        assert os.path.getsize(full_path) > 0

        # Verify PDF magic bytes
        with open(full_path, 'rb') as f:
            header = f.read(5)
            assert header == b'%PDF-', "Generated file is not a valid PDF document"

        # Verify Scan record linkage
        scan = db.session.get(Scan, sample_completed_scan)
        assert scan.report_path == report_record.file_path


def test_generate_report_requires_completed_scan(app, auth_user):
    """Verify that generating a report for a running or failed scan is rejected."""
    with app.app_context():
        running_scan = Scan(
            user_id=auth_user.id,
            target='127.0.0.1',
            scan_profile='basic_port_scan',
            status='running'
        )
        db.session.add(running_scan)
        db.session.commit()
        s_id = running_scan.id

        rep, err = generate_pdf_report(s_id, app=app)
        assert rep is None
        assert "must be in 'completed' status" in err


def test_safe_escape_and_code_formatter():
    """SEC-013: Verify safe XML escaping for arbitrary text and evidence blocks."""
    raw_payload = '<script>alert("XSS & Injection")</script>'
    escaped = safe_escape(raw_payload)
    assert '<script>' not in escaped
    assert '&lt;script&gt;' in escaped
    assert '&amp;' in escaped
    assert '&quot;' in escaped

    code_res = safe_code_text("line 1\nline 2")
    assert '<br/>' in code_res


def test_report_generation_with_special_characters(app, auth_user):
    """Verify that ReportLab does not crash when finding titles/evidence have special XML characters."""
    with app.app_context():
        scan = Scan(
            user_id=auth_user.id,
            target='192.168.1.50',
            scan_profile='basic_port_scan',
            status='completed'
        )
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, ip_address='192.168.1.50', state='up')
        db.session.add(host)
        db.session.flush()

        port = Port(host_id=host.id, port_number=80, protocol='tcp', state='open', service='http')
        db.session.add(port)
        db.session.flush()

        # Malicious finding with XML characters
        f = Finding(
            scan_id=scan.id,
            host_id=host.id,
            port_id=port.id,
            rule_id='NMAP-XSS-TEST',
            title='Vulnerability with <tags> & "quotes" & ampersands',
            severity='HIGH',
            description='Test <xml> injection & special characters in description.',
            evidence='Payload: <img src=x onerror=alert(1)> & <script>',
            remediation='Apply filter <safe> & encode all outputs.',
            status='OPEN'
        )
        db.session.add(f)
        db.session.commit()
        s_id = scan.id

        # Generating report must succeed without XML parsing errors
        rep, err = generate_pdf_report(s_id, app=app)
        assert err is None
        assert rep is not None
        assert rep.status == 'COMPLETED'


def test_download_report_endpoint(authenticated_client, sample_completed_scan):
    """Verify that the authenticated user can download their generated PDF report."""
    resp = authenticated_client.get(f'/report/download/{sample_completed_scan}')
    assert resp.status_code == 200
    assert resp.mimetype == 'application/pdf'
    assert 'attachment' in resp.headers.get('Content-Disposition', '')
    assert resp.data.startswith(b'%PDF-')


def test_api_generate_report_endpoint(authenticated_client, sample_completed_scan):
    """Verify the on-demand API endpoint returns report metadata."""
    resp = authenticated_client.post(f'/api/scans/{sample_completed_scan}/report')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'download_url' in data['report']
    assert data['report']['scan_id'] == sample_completed_scan
