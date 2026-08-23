import os
import logging
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, current_app, redirect, url_for, flash, Response, abort
from flask_login import login_required, current_user

from models import db, Scan, Host, Port, NSEResult, Finding
from services.target_validator import validate_target
from services.scan_profiles import get_scan_profiles, get_profile_by_id, is_valid_profile
from services.nmap_service import (
    start_scan_job,
    cancel_active_scan,
    is_scan_running,
    check_nmap_availability,
    ScanExecutionError,
    ScanConcurrencyError,
    ScanAuthorizationError,
    ScanProfileError
)
from services.parser import validate_xml_file, XMLSecurityError

logger = logging.getLogger(__name__)
scans_bp = Blueprint('scans', __name__)


# ---------------------------------------------------------------------------
#  Helper: ownership check (returns scan or aborts with 404)
# ---------------------------------------------------------------------------
def _get_authorized_scan(scan_id):
    """Fetch a scan by ID and verify ownership. Returns 404 to avoid leaking existence."""
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    return scan


# ---------------------------------------------------------------------------
#  PAGE: New Scan
# ---------------------------------------------------------------------------
@scans_bp.route('/scan/new')
@login_required
def new_scan():
    allowed_targets = current_app.config.get('ALLOWED_LAB_TARGETS', [])
    profiles = get_scan_profiles()
    nmap_status = check_nmap_availability(current_app.config.get('NMAP_PATH', 'nmap'))
    return render_template(
        'new_scan.html',
        allowed_targets=allowed_targets,
        profiles=profiles,
        nmap_status=nmap_status
    )


# ---------------------------------------------------------------------------
#  API: Validate Target
# ---------------------------------------------------------------------------
@scans_bp.route('/api/validate-target', methods=['POST'])
@login_required
def api_validate_target():
    """
    Validates and enforces authorization boundaries on candidate scan targets.
    """
    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            raw_target = data.get('target', '')
        else:
            raw_target = request.form.get('target', '')

        allowed_targets = current_app.config.get('ALLOWED_LAB_TARGETS', [])
        allow_private = current_app.config.get('ALLOW_PRIVATE_SUBNETS', True)
        allow_localhost = current_app.config.get('ALLOW_LOCALHOST', True)

        from models.authorized_target import AuthorizedTarget
        db_auth_targets = AuthorizedTarget.query.all()
        for at in db_auth_targets:
            allowed_targets.append(at.target)

        username = current_user.username if current_user and current_user.is_authenticated else 'unknown'

        result = validate_target(
            target=raw_target,
            authorized_targets=allowed_targets,
            allow_private_subnets=allow_private,
            allow_localhost=allow_localhost
        )

        return jsonify({
            "valid": result['valid'],
            "target": result['target'],
            "type": result['type'],
            "authorized": result['authorized'],
            "message": result['message']
        }), 200

    except Exception as e:
        logger.error(f"Unexpected error during target validation: {str(e)}")
        return jsonify({
            "valid": False,
            "authorized": False,
            "message": "An error occurred while validating the target. Please verify format and try again."
        }), 500


# ---------------------------------------------------------------------------
#  API: Scan Profiles
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scan-profiles', methods=['GET'])
@login_required
def api_get_scan_profiles():
    """Returns the immutable catalog of predefined scan profiles."""
    return jsonify(get_scan_profiles()), 200


# ---------------------------------------------------------------------------
#  API: List Scans (GET) & Start Scan (POST)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans', methods=['GET'])
@login_required
def api_get_scans():
    """Returns a list of scans owned by the current user with search/filtering/pagination."""
    search_query = request.args.get('q', '').strip()
    status_filter = request.args.get('status', '').strip().lower()
    profile_filter = request.args.get('profile', '').strip()
    sort_by = request.args.get('sort', 'newest').strip().lower()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = max(1, min(per_page, 100))

    query = Scan.query.filter_by(user_id=current_user.id)

    if search_query:
        s_like = f"%{search_query}%"
        try:
            search_id = int(search_query)
            query = query.filter(
                (Scan.target.ilike(s_like)) |
                (Scan.scan_profile.ilike(s_like)) |
                (Scan.id == search_id)
            )
        except ValueError:
            query = query.filter(
                (Scan.target.ilike(s_like)) |
                (Scan.scan_profile.ilike(s_like))
            )

    valid_statuses = ['pending', 'running', 'completed', 'failed', 'timeout', 'cancelled']
    if status_filter and status_filter in valid_statuses:
        query = query.filter(Scan.status == status_filter)

    if profile_filter:
        query = query.filter(Scan.scan_profile == profile_filter)

    if sort_by == 'oldest':
        query = query.order_by(Scan.start_time.asc())
    elif sort_by == 'target':
        query = query.order_by(Scan.target.asc(), Scan.start_time.desc())
    elif sort_by == 'duration':
        query = query.order_by(Scan.duration.desc().nullslast(), Scan.start_time.desc())
    elif sort_by == 'findings':
        query = query.order_by(Scan.number_of_findings.desc().nullslast(), Scan.start_time.desc())
    elif sort_by == 'status':
        query = query.order_by(Scan.status.asc(), Scan.start_time.desc())
    else:
        query = query.order_by(Scan.start_time.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    scans_data = [s.to_dict() for s in pagination.items]

    return jsonify({
        "scans": scans_data,
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": pagination.per_page,
        "has_prev": pagination.has_prev,
        "has_next": pagination.has_next
    }), 200


@scans_bp.route('/api/scans', methods=['POST'])
@login_required
def api_start_scan():
    """
    Initiates a new scan execution against a validated target using a predefined profile.
    """
    try:
        if request.is_json:
            data = request.get_json(silent=True) or {}
            target = data.get('target', '')
            profile_id = data.get('profile', '')
        else:
            target = request.form.get('target', '')
            profile_id = request.form.get('profile', '')

        if not target or not profile_id:
            return jsonify({
                "success": False,
                "message": "Target and predefined scan profile are required."
            }), 400

        # Dispatch scan through Nmap service
        app = current_app._get_current_object()
        scan_record, msg = start_scan_job(
            app=app,
            user_id=current_user.id,
            target=target,
            profile_id=profile_id
        )

        return jsonify({
            "success": True,
            "scan_id": scan_record.id,
            "status": "running",
            "message": msg,
            "redirect_url": url_for('scans.scan_progress', scan_id=scan_record.id)
        }), 201

    except ScanConcurrencyError as sce:
        return jsonify({
            "success": False,
            "message": str(sce)
        }), 429
    except (ScanAuthorizationError, ScanProfileError) as se:
        return jsonify({
            "success": False,
            "message": str(se)
        }), 400
    except Exception as e:
        logger.error(f"Failed to launch scan: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An unexpected error occurred while initializing the scan process."
        }), 500


# ---------------------------------------------------------------------------
#  API: Get Scan Details
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>', methods=['GET'])
@login_required
def api_get_scan_details(scan_id):
    """Returns structured scan data including hosts, ports, and NSE results."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized API scan details access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    hosts_data = []
    for host in scan.hosts:
        ports_list = [{
            'port_number': p.port_number,
            'protocol': p.protocol,
            'state': p.state,
            'service': p.service,
            'product': p.product,
            'version': p.version,
            'extra_info': p.extra_info
        } for p in host.ports]

        scripts_list = [{
            'script_id': n.script_id,
            'service': n.service,
            'output': n.output,
            'severity': n.severity
        } for n in host.nse_results]

        hosts_data.append({
            'id': host.id,
            'ip_address': host.ip_address,
            'hostname': host.hostname,
            'state': host.state,
            'os_information': host.os_information,
            'ports': ports_list,
            'scripts': scripts_list
        })

    # Compute real counts
    total_findings = len(scan.findings)
    findings_by_severity = {}
    for f in scan.findings:
        sev = f.severity.upper()
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

    return jsonify({
        "id": scan.id,
        "target": scan.target,
        "scan_profile": scan.scan_profile,
        "status": scan.status.upper(),
        "start_time": scan.start_time.isoformat() if scan.start_time else None,
        "end_time": scan.end_time.isoformat() if scan.end_time else None,
        "duration": round(scan.duration, 2) if scan.duration else None,
        "number_of_hosts": scan.number_of_hosts or len(scan.hosts),
        "number_of_open_ports": scan.number_of_open_ports or sum(1 for h in scan.hosts for p in h.ports if p.state == 'open'),
        "hosts": hosts_data,
        "findings_count": total_findings,
        "findings_by_severity": findings_by_severity,
        "nse_count": len(scan.nse_results),
        "error_message": scan.error_message
    }), 200


# ---------------------------------------------------------------------------
#  API: Scan Status
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/status', methods=['GET'])
@login_required
def api_scan_status(scan_id):
    """Returns real-time status telemetry for a scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized API scan status access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    profile = get_profile_by_id(scan.scan_profile)
    profile_name = profile['name'] if profile else scan.scan_profile

    # Calculate elapsed duration if still running
    elapsed_seconds = None
    if scan.start_time:
        if scan.end_time:
            elapsed_seconds = (scan.end_time - scan.start_time).total_seconds()
        elif scan.status == 'running':
            elapsed_seconds = (datetime.utcnow() - scan.start_time).total_seconds()

    return jsonify({
        "id": scan.id,
        "target": scan.target,
        "profile_id": scan.scan_profile,
        "profile_name": profile_name,
        "status": scan.status,
        "is_running": scan.status == 'running',
        "start_time": scan.start_time.strftime('%b %d, %Y %I:%M:%S %p') if scan.start_time else None,
        "end_time": scan.end_time.strftime('%b %d, %Y %I:%M:%S %p') if scan.end_time else None,
        "duration": round(scan.duration, 2) if scan.duration else (round(elapsed_seconds, 2) if elapsed_seconds is not None else None),
        "has_xml": bool(scan.xml_path),
        "error_message": scan.error_message,
        "redirect_results_url": url_for('scans.scan_results', scan_id=scan.id)
    }), 200


# ---------------------------------------------------------------------------
#  API: Cancel Scan
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/cancel', methods=['POST'])
@login_required
def api_cancel_scan(scan_id):
    """Cancels an active scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized cancel attempt on scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    success = cancel_active_scan(scan_id)
    if scan.status == 'running':
        scan.status = 'cancelled'
        scan.end_time = datetime.utcnow()
        scan.error_message = "Scan cancelled by auditor."
        db.session.commit()

    return jsonify({
        "success": True,
        "message": "Scan cancelled." if success else "Scan was not actively running."
    }), 200


# ---------------------------------------------------------------------------
#  API: Delete Scan (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@login_required
def api_delete_scan(scan_id):
    """Transactionally deletes a scan and all associated records."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized delete attempt on scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    scan_target = scan.target
    try:
        # Remove XML file from disk if it exists
        if scan.xml_path:
            try:
                xml_full_path = os.path.join(current_app.config['SCANS_FOLDER'], scan.xml_path) if not os.path.isabs(scan.xml_path) else scan.xml_path
                if os.path.exists(xml_full_path):
                    os.remove(xml_full_path)
                    # Try removing parent scan directory if empty
                    scan_dir = os.path.dirname(xml_full_path)
                    if os.path.isdir(scan_dir) and not os.listdir(scan_dir):
                        os.rmdir(scan_dir)
            except OSError as oe:
                logger.warning(f"Could not remove XML file for scan #{scan_id}: {oe}")

        # Cascade delete handles hosts, ports, nse_results, findings, reports
        db.session.delete(scan)
        db.session.commit()

        logger.info(f"Scan #{scan_id} (target: {scan_target}) deleted by user {current_user.username}")

        return jsonify({
            "success": True,
            "message": f"Scan #{scan_id} and all associated data deleted successfully."
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting scan #{scan_id}: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An error occurred while deleting the scan."
        }), 500


# ---------------------------------------------------------------------------
#  API: Rescan (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/rescan', methods=['POST'])
@login_required
def api_rescan(scan_id):
    """Creates a new scan using the original scan's target and profile."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized rescan attempt on scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    try:
        app = current_app._get_current_object()
        new_scan, msg = start_scan_job(
            app=app,
            user_id=current_user.id,
            target=scan.target,
            profile_id=scan.scan_profile
        )

        logger.info(f"Rescan initiated: new scan #{new_scan.id} from scan #{scan_id} by user {current_user.username}")

        return jsonify({
            "success": True,
            "scan_id": new_scan.id,
            "message": f"Rescan initiated. New scan #{new_scan.id} created.",
            "redirect_url": url_for('scans.scan_progress', scan_id=new_scan.id)
        }), 201

    except ScanConcurrencyError as sce:
        return jsonify({"success": False, "message": str(sce)}), 429
    except (ScanAuthorizationError, ScanProfileError) as se:
        return jsonify({"success": False, "message": str(se)}), 400
    except Exception as e:
        logger.error(f"Rescan failed for scan #{scan_id}: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An error occurred while initiating the rescan."
        }), 500


# ---------------------------------------------------------------------------
#  API: Scan-scoped Hosts (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/hosts', methods=['GET'])
@login_required
def api_scan_hosts(scan_id):
    """Returns hosts belonging to a specific scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized hosts access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    hosts = Host.query.filter_by(scan_id=scan_id).all()
    result = []
    for h in hosts:
        open_ports = sum(1 for p in h.ports if p.state == 'open')
        result.append({
            'id': h.id,
            'ip_address': h.ip_address,
            'hostname': h.hostname,
            'state': h.state,
            'os_information': h.os_information,
            'total_ports': len(h.ports),
            'open_ports': open_ports,
            'findings_count': len(h.findings)
        })

    return jsonify(result), 200


# ---------------------------------------------------------------------------
#  API: Scan-scoped Ports (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/ports', methods=['GET'])
@login_required
def api_scan_ports(scan_id):
    """Returns ports belonging to a specific scan, with optional state filter."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized ports access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    state_filter = request.args.get('state', '').lower()

    query = Port.query.join(Host).filter(Host.scan_id == scan_id)
    if state_filter and state_filter in ('open', 'closed', 'filtered'):
        query = query.filter(Port.state.ilike(state_filter))

    ports = query.all()
    result = []
    for p in ports:
        result.append({
            'id': p.id,
            'host_ip': p.host.ip_address,
            'hostname': p.host.hostname,
            'port_number': p.port_number,
            'protocol': p.protocol,
            'state': p.state,
            'service': p.service,
            'product': p.product,
            'version': p.version,
            'extra_info': p.extra_info
        })

    return jsonify(result), 200


# ---------------------------------------------------------------------------
#  API: Scan-scoped Services (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/services', methods=['GET'])
@login_required
def api_scan_services(scan_id):
    """Returns unique services detected in a specific scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized services access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    ports = Port.query.join(Host).filter(Host.scan_id == scan_id, Port.state.ilike('open')).all()
    services = {}
    for p in ports:
        svc_name = p.service or 'unknown'
        if svc_name not in services:
            services[svc_name] = {
                'name': svc_name,
                'count': 0,
                'ports': []
            }
        services[svc_name]['count'] += 1
        services[svc_name]['ports'].append({
            'port_number': p.port_number,
            'protocol': p.protocol,
            'host_ip': p.host.ip_address,
            'product': p.product,
            'version': p.version
        })

    return jsonify(list(services.values())), 200


# ---------------------------------------------------------------------------
#  API: Scan-scoped NSE Results (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/nse', methods=['GET'])
@login_required
def api_scan_nse_results(scan_id):
    """Returns NSE results belonging to a specific scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized NSE access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    nse_results = NSEResult.query.filter_by(scan_id=scan_id).all()
    result = []
    for n in nse_results:
        result.append({
            'id': n.id,
            'script_id': n.script_id,
            'host_ip': n.host.ip_address if n.host else None,
            'port_number': n.port_number,
            'service': n.service,
            'status': n.status,
            'severity': n.severity,
            'description': n.description,
            'output': n.output,
            'error_message': n.error_message
        })

    return jsonify(result), 200


# ---------------------------------------------------------------------------
#  API: Scan-scoped Findings (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/findings', methods=['GET'])
@login_required
def api_scan_findings(scan_id):
    """Returns findings belonging to a specific scan, with optional severity filter."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized findings access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    severity_filter = request.args.get('severity', '').lower()

    query = Finding.query.filter_by(scan_id=scan_id)
    if severity_filter and severity_filter in ('high', 'medium', 'low', 'info', 'critical'):
        query = query.filter(Finding.severity.ilike(severity_filter))

    findings = query.all()
    result = []
    for f in findings:
        result.append({
            'id': f.id,
            'rule_id': f.rule_id,
            'title': f.title,
            'severity': f.severity,
            'category': f.category,
            'confidence': f.confidence,
            'observation_type': f.observation_type,
            'status': f.status,
            'host_ip': f.host.ip_address if f.host else None,
            'port_info': f"{f.port.port_number}/{f.port.protocol}" if f.port else "—",
            'service': f.port.service if f.port else "—",
            'description': f.description,
            'evidence': f.evidence,
            'remediation': f.remediation or f.recommendation,
            'created_at': f.created_at.isoformat() if f.created_at else None
        })

    return jsonify(result), 200


# ---------------------------------------------------------------------------
#  API: Finding Detail (Phase 10)
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/findings/<int:finding_id>', methods=['GET'])
@login_required
def api_finding_detail(scan_id, finding_id):
    """Returns detailed information for a specific finding within a scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized finding detail access to scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    finding = db.session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        return jsonify({"error": "Finding not found"}), 404

    return jsonify({
        'id': finding.id,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'category': finding.category,
        'confidence': finding.confidence,
        'observation_type': finding.observation_type,
        'status': finding.status,
        'description': finding.description,
        'evidence': finding.evidence,
        'recommendation': finding.recommendation,
        'remediation': finding.remediation,
        'classification': finding.classification,
        'host_ip': finding.host.ip_address if finding.host else None,
        'hostname': finding.host.hostname if finding.host else None,
        'port_info': f"{finding.port.port_number}/{finding.port.protocol}" if finding.port else "—",
        'service': finding.port.service if finding.port else "—",
        'created_at': finding.created_at.isoformat() if finding.created_at else None
    }), 200


# ---------------------------------------------------------------------------
#  PAGE: Scan Progress
# ---------------------------------------------------------------------------
@scans_bp.route('/scan/progress/<int:scan_id>')
@login_required
def scan_progress(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)

    profile = get_profile_by_id(scan.scan_profile)
    return render_template('scan_progress.html', scan=scan, profile=profile)


# ---------------------------------------------------------------------------
#  PAGE: Scan Results / Detailed View (Phase 10 enhanced)
# ---------------------------------------------------------------------------
@scans_bp.route('/scan/results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)

    # If scan is completed and xml_path exists but hosts not parsed yet, parse on-demand
    if scan.status == 'completed' and scan.xml_path and len(scan.hosts) == 0:
        try:
            from services.parser import parse_and_store_scan
            parse_and_store_scan(scan.id, scan.xml_path)
            db.session.refresh(scan)
        except Exception as pe:
            logger.error(f"Error parsing scan #{scan_id} XML on-demand: {str(pe)}")

    profile = get_profile_by_id(scan.scan_profile)
    hosts = Host.query.filter_by(scan_id=scan.id).all()
    nse_results = NSEResult.query.filter_by(scan_id=scan.id).all()
    findings = Finding.query.filter_by(scan_id=scan.id).all()

    # Aggregate open port count across hosts
    all_ports = []
    for h in hosts:
        for p in h.ports:
            all_ports.append({
                'host_ip': h.ip_address,
                'hostname': h.hostname,
                'port': p.port_number,
                'protocol': p.protocol,
                'state': p.state,
                'service': p.service or 'unknown',
                'product': p.product or '—',
                'version': p.version or '—',
                'extra_info': p.extra_info or '—'
            })

    # Compute findings severity counts
    findings_high = sum(1 for f in findings if f.severity.lower() == 'high')
    findings_medium = sum(1 for f in findings if f.severity.lower() == 'medium')
    findings_low = sum(1 for f in findings if f.severity.lower() == 'low')
    findings_info = sum(1 for f in findings if f.severity.lower() == 'info')

    # Compute scan statistics
    open_ports_count = sum(1 for p in all_ports if p['state'] == 'open')
    closed_ports_count = sum(1 for p in all_ports if p['state'] == 'closed')
    filtered_ports_count = sum(1 for p in all_ports if p['state'] == 'filtered')
    unique_services = len(set(p['service'] for p in all_ports if p['service'] != 'unknown'))
    hosts_up = sum(1 for h in hosts if h.state == 'up')

    scan_stats = {
        'total_hosts': len(hosts),
        'hosts_up': hosts_up,
        'total_ports': len(all_ports),
        'open_ports': open_ports_count,
        'closed_ports': closed_ports_count,
        'filtered_ports': filtered_ports_count,
        'unique_services': unique_services,
        'nse_results': len(nse_results),
        'findings': len(findings)
    }

    logger.info(f"Scan #{scan_id} detailed results accessed by user {current_user.username}")

    return render_template(
        'scan_results.html',
        scan=scan,
        profile=profile,
        hosts=hosts,
        nse_results=nse_results,
        all_ports=all_ports,
        findings=findings,
        findings_high=findings_high,
        findings_medium=findings_medium,
        findings_low=findings_low,
        findings_info=findings_info,
        scan_stats=scan_stats
    )


# ---------------------------------------------------------------------------
#  PAGE: Raw XML Download
# ---------------------------------------------------------------------------
@scans_bp.route('/scan/raw-xml/<int:scan_id>')
@login_required
def raw_xml(scan_id):
    """
    Safely exposes XML content or metadata for an authorized scan owned by current_user.
    """
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized XML access attempt for scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan XML."}), 403

    if not scan.xml_path:
        return jsonify({"error": "No XML artifact available for this scan."}), 404

    try:
        validated_path = validate_xml_file(scan.xml_path, allowed_base_dir=current_app.config['SCANS_FOLDER'])
        
        # Check download flag
        download = request.args.get('download', '0') == '1'
        with open(validated_path, 'r', encoding='utf-8', errors='replace') as f:
            xml_content = f.read()

        logger.info(f"XML artifact accessed for scan #{scan_id} (download={download}) by user {current_user.username}")

        if download:
            filename = f"scan_{scan.id}_result.xml"
            return Response(
                xml_content,
                mimetype='application/xml',
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )

        return Response(xml_content, mimetype='application/xml')

    except XMLSecurityError as se:
        logger.error(f"Security error accessing XML for scan #{scan_id}: {str(se)}")
        return jsonify({"error": "Invalid or unauthorized XML path."}), 403
    except Exception as e:
        logger.error(f"Error reading XML file for scan #{scan_id}: {str(e)}")
        return jsonify({"error": "Unable to load scan XML results."}), 500


# ---------------------------------------------------------------------------
#  PAGE: Scan History (Phase 10 — full search/filter/sort/pagination)
# ---------------------------------------------------------------------------
@scans_bp.route('/scan/history')
@login_required
def scan_history():
    logger.info(f"Scan history accessed by user {current_user.username}")

    # Query parameters
    search_query = request.args.get('q', '').strip()
    status_filter = request.args.get('status', '').strip().lower()
    profile_filter = request.args.get('profile', '').strip()
    sort_by = request.args.get('sort', 'newest').strip().lower()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    # Clamp per_page
    per_page = max(5, min(per_page, 100))

    # Base query — user's scans only
    query = Scan.query.filter_by(user_id=current_user.id)

    # Search (target, scan_id, profile)
    if search_query:
        s_like = f"%{search_query}%"
        # If search is numeric, also match scan ID
        try:
            search_id = int(search_query)
            query = query.filter(
                (Scan.target.ilike(s_like)) |
                (Scan.scan_profile.ilike(s_like)) |
                (Scan.id == search_id)
            )
        except ValueError:
            query = query.filter(
                (Scan.target.ilike(s_like)) |
                (Scan.scan_profile.ilike(s_like))
            )

    # Status filter
    valid_statuses = ['pending', 'running', 'completed', 'failed', 'timeout', 'cancelled']
    if status_filter and status_filter in valid_statuses:
        query = query.filter(Scan.status == status_filter)

    # Profile filter
    if profile_filter:
        query = query.filter(Scan.scan_profile == profile_filter)

    # Sorting
    if sort_by == 'oldest':
        query = query.order_by(Scan.start_time.asc())
    elif sort_by == 'target':
        query = query.order_by(Scan.target.asc(), Scan.start_time.desc())
    elif sort_by == 'duration':
        query = query.order_by(Scan.duration.desc().nullslast(), Scan.start_time.desc())
    elif sort_by == 'findings':
        query = query.order_by(Scan.number_of_findings.desc().nullslast(), Scan.start_time.desc())
    elif sort_by == 'status':
        query = query.order_by(Scan.status.asc(), Scan.start_time.desc())
    else:  # newest (default)
        query = query.order_by(Scan.start_time.desc())

    # Pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    scans = pagination.items

    # Get available profiles for filter dropdown
    profiles = get_scan_profiles()

    return render_template(
        'history.html',
        scans=scans,
        pagination=pagination,
        profiles=profiles,
        search_query=search_query,
        status_filter=status_filter,
        profile_filter=profile_filter,
        sort_by=sort_by,
        per_page=per_page
    )


# ---------------------------------------------------------------------------
#  API: Trigger NSE Scripts
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/nse', methods=['POST'])
@login_required
def api_trigger_nse(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized NSE trigger attempt on scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    if scan.status != 'completed':
        return jsonify({"error": f"Scan must be completed to run NSE. Current status: {scan.status}"}), 400

    from services.nse_service import execute_nse_scripts_for_scan
    app = current_app._get_current_object()
    success = execute_nse_scripts_for_scan(scan_id, app)
    
    if success:
        return jsonify({
            "success": True,
            "message": "Predefined NSE Script analysis completed successfully."
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "Failed to execute NSE Script analysis."
        }), 500


# ---------------------------------------------------------------------------
#  API: Trigger Findings Analyzer
# ---------------------------------------------------------------------------
@scans_bp.route('/api/scans/<int:scan_id>/analyze', methods=['POST'])
@login_required
def api_trigger_analyze(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan.user_id != current_user.id:
        logger.warning(f"Unauthorized analyze trigger attempt on scan #{scan_id} by user {current_user.username}")
        return jsonify({"error": "Unauthorized access to scan."}), 403

    if scan.status != 'completed':
        return jsonify({"error": f"Scan must be completed to run findings analyzer. Current status: {scan.status}"}), 400

    from services.findings_analyzer import analyze_scan_results
    app = current_app._get_current_object()
    success = analyze_scan_results(scan_id, app)
    
    if success:
        return jsonify({
            "success": True,
            "message": "Findings analysis completed successfully."
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "Failed to run findings analysis."
        }), 500


# ---------------------------------------------------------------------------
#  Aliases
# ---------------------------------------------------------------------------
@scans_bp.route('/scans/<int:scan_id>')
@login_required
def scan_detail_alias(scan_id):
    """Direct route alias for /scan/results/<scan_id>."""
    return scan_results(scan_id)


@scans_bp.route('/history')
@login_required
def history_alias():
    return redirect(url_for('scans.scan_history'))
