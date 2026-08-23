from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app
from flask_login import login_required, current_user
from models import db
from models.authorized_target import AuthorizedTarget
from services.target_validator import validate_target
import ipaddress

authorized_targets_bp = Blueprint('authorized_targets', __name__)

@authorized_targets_bp.route('/authorized-targets', methods=['GET'])
@login_required
def manage_targets():
    # Only authenticated users can access, further restrictions could check current_user.role if it existed.
    targets = AuthorizedTarget.query.order_by(AuthorizedTarget.created_at.desc()).all()
    return render_template('authorized_targets.html', targets=targets)

@authorized_targets_bp.route('/authorized-targets', methods=['POST'])
@login_required
def add_target():
    raw_target = request.form.get('target', '').strip()
    
    if not raw_target:
        flash("Target cannot be empty.", "danger")
        return redirect(url_for('authorized_targets.manage_targets'))

    # Preliminary validation using the target_validator without authorized list
    # to avoid chicken-and-egg issue.
    val = validate_target(raw_target, authorized_targets=[], allow_private_subnets=True, allow_localhost=True)
    
    if not val['valid'] or not val['type']:
        flash(val['message'] or "Invalid target format.", "danger")
        return redirect(url_for('authorized_targets.manage_targets'))
        
    canonical_target = val['target']
    t_type = val['type']

    existing = AuthorizedTarget.query.filter_by(target=canonical_target).first()
    if existing:
        flash(f"Target {canonical_target} is already authorized.", "warning")
        return redirect(url_for('authorized_targets.manage_targets'))

    new_auth_target = AuthorizedTarget(
        target=canonical_target,
        target_type=t_type,
        added_by=current_user.id
    )
    
    try:
        db.session.add(new_auth_target)
        db.session.commit()
        flash(f"Target {canonical_target} explicitly authorized.", "success")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error saving authorized target: {e}")
        flash("An error occurred while saving the target.", "danger")

    return redirect(url_for('authorized_targets.manage_targets'))
