"""
tests/test_path_traversal.py
============================
Path Traversal and File Boundary Security Tests.
Verifies that directory traversal sequences (../, ..\\, %2e%2e/) cannot escape
designated scan and report storage directories.
"""

import os
import pytest
from services.parser import validate_xml_file, XMLSecurityError
from services.report_generator import validate_report_file, ReportSecurityError
from models import db, Scan, Report

TRAVERSAL_PATHS = [
    "../../etc/passwd",
    "..\\..\\Windows\\System32\\calc.exe",
    "....//....//etc/shadow",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "scans/../config.py",
    "reports/../../app.py",
    "%2e%2e/%2e%2e/config.py",
]

def test_validate_xml_file_rejects_traversal(tmp_path):
    """SEC-010: validate_xml_file must reject paths resolving outside the allowed base directory."""
    base_dir = str(tmp_path / 'scans')
    os.makedirs(base_dir, exist_ok=True)

    # Create an outside secret file
    outside_file = tmp_path / 'secret.txt'
    outside_file.write_text("SUPER_SECRET_TOKEN_DO_NOT_EXPOSE")

    # Path traversal attempts
    traversal_candidate = os.path.join(base_dir, '..', 'secret.txt')

    with pytest.raises(XMLSecurityError):
        validate_xml_file(traversal_candidate, allowed_base_dir=base_dir)

    for p in TRAVERSAL_PATHS:
        with pytest.raises(XMLSecurityError):
            validate_xml_file(p, allowed_base_dir=base_dir)


def test_validate_xml_file_accepts_valid_file(tmp_path):
    """Verify that a valid XML file within the allowed directory passes validation."""
    base_dir = str(tmp_path / 'scans')
    os.makedirs(base_dir, exist_ok=True)

    valid_file = os.path.join(base_dir, 'scan_1', 'result.xml')
    os.makedirs(os.path.dirname(valid_file), exist_ok=True)
    with open(valid_file, 'w', encoding='utf-8') as f:
        f.write("<nmaprun></nmaprun>")

    canonical = validate_xml_file(valid_file, allowed_base_dir=base_dir)
    assert canonical == os.path.abspath(valid_file)


def test_validate_report_file_rejects_traversal(tmp_path):
    """SEC-011: validate_report_file must reject report paths resolving outside REPORTS_FOLDER."""
    base_dir = str(tmp_path / 'reports')
    os.makedirs(base_dir, exist_ok=True)

    outside_file = tmp_path / 'outside_doc.pdf'
    outside_file.write_bytes(b"%PDF-1.4 dummy")

    traversal_candidate = os.path.join(base_dir, '..', 'outside_doc.pdf')

    with pytest.raises(ReportSecurityError):
        validate_report_file(traversal_candidate, allowed_base_dir=base_dir)

    for p in TRAVERSAL_PATHS:
        with pytest.raises(ReportSecurityError):
            validate_report_file(p, allowed_base_dir=base_dir)


def test_scan_xml_download_blocks_tampered_path(app, authenticated_client, sample_completed_scan, tmp_path):
    """SEC-010: Ensure /scan/raw-xml route blocks access if scan.xml_path points outside SCANS_FOLDER."""
    with app.app_context():
        scan = db.session.get(Scan, sample_completed_scan)
        # Maliciously attempt to point scan.xml_path to config.py
        scan.xml_path = os.path.abspath(os.path.join(app.config['BASE_DIR'], 'config.py'))
        db.session.commit()

    resp = authenticated_client.get(f'/scan/raw-xml/{sample_completed_scan}')
    assert resp.status_code in (403, 500), "Tampered XML path allowed unauthorized file exposure"
