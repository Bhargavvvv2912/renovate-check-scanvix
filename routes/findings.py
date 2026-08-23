from flask import Blueprint, render_template
from flask_login import login_required, current_user
from models import db, Finding, Scan

findings_bp = Blueprint('findings', __name__)

@findings_bp.route('/findings')
@login_required
def index():
    findings = Finding.query.join(Scan).filter(Scan.user_id == current_user.id).all()
    # Compute severities for dashboard cards
    high_count = sum(1 for f in findings if f.severity.lower() == 'high')
    medium_count = sum(1 for f in findings if f.severity.lower() == 'medium')
    low_count = sum(1 for f in findings if f.severity.lower() == 'low')
    info_count = sum(1 for f in findings if f.severity.lower() == 'info')
    
    return render_template(
        'findings.html',
        findings=findings,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count
    )

@findings_bp.route('/api/findings')
@login_required
def api_findings():
    from flask import request, jsonify
    
    severity = request.args.get('severity')
    category = request.args.get('category')
    confidence = request.args.get('confidence')
    obs_type = request.args.get('observation_type')
    host = request.args.get('host')
    search = request.args.get('search')
    
    query = Finding.query.join(Scan).filter(Scan.user_id == current_user.id)
    
    if severity:
        query = query.filter(Finding.severity.ilike(severity))
    if category:
        query = query.filter(Finding.category.ilike(category))
    if confidence:
        query = query.filter(Finding.confidence.ilike(confidence))
    if obs_type:
        query = query.filter(Finding.observation_type.ilike(obs_type))
    if host:
        from models.host import Host
        query = query.join(Host, Finding.host_id == Host.id).filter(Host.ip_address.ilike(f"%{host}%"))
        
    if search:
        s_like = f"%{search}%"
        # Search by title, rule_id, description, evidence
        query = query.filter(
            (Finding.title.ilike(s_like)) |
            (Finding.rule_id.ilike(s_like)) |
            (Finding.description.ilike(s_like)) |
            (Finding.evidence.ilike(s_like))
        )
        
    findings = query.all()
    results = []
    for f in findings:
        results.append({
            'id': f.id,
            'rule_id': f.rule_id,
            'title': f.title,
            'severity': f.severity,
            'category': f.category,
            'confidence': f.confidence,
            'observation_type': f.observation_type,
            'status': f.status,
            'host_ip': f.host.ip_address,
            'port_info': f"{f.port.port_number}/{f.port.protocol}" if f.port else "—",
            'service': f.port.service if f.port else "—",
            'description': f.description,
            'evidence': f.evidence,
            'remediation': f.remediation or f.recommendation
        })
    return jsonify(results)

@findings_bp.route('/api/findings/<int:finding_id>/status', methods=['POST'])
@login_required
def update_finding_status(finding_id):
    from flask import request, jsonify
    
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404
        
    # Ownership boundary validation
    if finding.scan.user_id != current_user.id:
        return jsonify({"error": "Unauthorized access to finding."}), 403
        
    data = request.get_json(silent=True) or {}
    new_status = (data.get('status', '')).upper().strip()
    
    if new_status not in ('OPEN', 'ACKNOWLEDGED', 'RESOLVED'):
        return jsonify({"error": "Invalid status value. Must be OPEN, ACKNOWLEDGED, or RESOLVED."}), 400
        
    finding.status = new_status
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": f"Finding status updated to {new_status} successfully.",
        "status": new_status
    }), 200

