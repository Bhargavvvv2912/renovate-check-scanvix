import os
import logging
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, current_app, send_file, abort
from flask_login import login_required, current_user

from models import db, Scan, Host, Port, NSEResult, Finding, Report
from services.report_generator import generate_pdf_report, validate_report_file, ReportSecurityError
from routes.scans import scan_history

logger = logging.getLogger(__name__)
reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/reports')
@reports_bp.route('/exported-reports')
@login_required
def index():
    """Renders the reports / scan history index."""
    return scan_history()


@reports_bp.route('/report/view/<int:scan_id>')
@login_required
def view_report(scan_id):
    """
    Renders the report preview page for an authorized scan.
    Verifies user ownership before rendering.
    """
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)

    report = Report.query.filter_by(scan_id=scan.id).first()
    hosts = Host.query.filter_by(scan_id=scan.id).all()
    findings = Finding.query.filter_by(scan_id=scan.id).all()

    return render_template(
        'report.html',
        scan=scan,
        report=report,
        hosts=hosts,
        findings=findings
    )


@reports_bp.route('/report/download/<int:scan_id>')
@login_required
def download_report(scan_id):
    """
    Generates (if needed) and securely streams the PDF assessment report for download.
    Enforces user ownership and strict path traversal validation.
    """
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized report download attempt on scan #{scan_id} by user {current_user.username}")
        abort(403)

    if scan.status != 'completed':
        return jsonify({"error": f"Cannot download report for scan in '{scan.status}' status."}), 400

    reports_base_dir = current_app.config.get('REPORTS_FOLDER', os.path.join(current_app.root_path, 'reports'))

    # If report not generated or file missing, generate now
    report_record = Report.query.filter_by(scan_id=scan.id).first()
    file_full_path = None
    if report_record and report_record.file_path:
        candidate_path = report_record.file_path if os.path.isabs(report_record.file_path) else os.path.join(current_app.root_path, report_record.file_path)
        if os.path.exists(candidate_path):
            file_full_path = candidate_path

    if not file_full_path:
        app_obj = current_app._get_current_object()
        report_record, err = generate_pdf_report(scan.id, app=app_obj)
        if err or not report_record:
            logger.error(f"Failed on-demand PDF report generation for scan #{scan_id}: {err}")
            return jsonify({"error": f"Failed to generate report: {err}"}), 500
        file_full_path = report_record.file_path if os.path.isabs(report_record.file_path) else os.path.join(current_app.root_path, report_record.file_path)

    try:
        # Validate path boundary against traversal attacks
        validated_file = validate_report_file(file_full_path, allowed_base_dir=reports_base_dir)
        download_filename = f"ScanVix_Security_Report_{scan.id}.pdf"
        logger.info(f"User {current_user.username} downloaded report for scan #{scan_id}")
        return send_file(
            validated_file,
            as_attachment=True,
            download_name=download_filename,
            mimetype='application/pdf'
        )
    except ReportSecurityError as rse:
        logger.error(f"Security error accessing report file for scan #{scan_id}: {str(rse)}")
        return jsonify({"error": "Unauthorized or invalid report file path."}), 403
    except Exception as e:
        logger.error(f"Error streaming PDF report for scan #{scan_id}: {str(e)}")
        return jsonify({"error": "Unable to serve report file."}), 500


@reports_bp.route('/api/scans/<int:scan_id>/report', methods=['POST'])
@login_required
def api_generate_report(scan_id):
    """
    On-demand API endpoint to trigger PDF report generation.
    Returns report metadata and download URL.
    """
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized API report generate attempt on scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    if scan.status != 'completed':
        return jsonify({"error": f"Scan must be in 'completed' status to generate report. Current: {scan.status}"}), 400

    app_obj = current_app._get_current_object()
    report_record, err = generate_pdf_report(scan_id, app=app_obj)

    if err:
        return jsonify({"success": False, "message": err}), 500

    return jsonify({
        "success": True,
        "message": "PDF Security Assessment Report generated successfully.",
        "report": {
            "id": report_record.id,
            "report_id": report_record.report_id,
            "scan_id": report_record.scan_id,
            "file_size": report_record.file_size,
            "status": report_record.status,
            "generated_at": report_record.generated_at.isoformat() if report_record.generated_at else None,
            "download_url": url_for('reports.download_report', scan_id=scan.id)
        }
    }), 200


@reports_bp.route('/api/reports', methods=['GET'])
@login_required
def api_list_reports():
    """Returns a list of generated reports for scans owned by the current user."""
    reports = Report.query.join(Scan).filter(Scan.user_id == current_user.id).order_by(Report.generated_at.desc()).all()
    data = []
    for r in reports:
        item = r.to_dict()
        item['download_url'] = url_for('reports.download_report', scan_id=r.scan_id)
        data.append(item)
    return jsonify({"reports": data, "total": len(data)}), 200
