import logging
from urllib.parse import urlparse, urljoin
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models.user import User

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

def is_safe_url(target):
    """Ensure redirect targets stay on the same domain to prevent open redirect vulnerabilities."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard_alias'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Invalid username or password.", "danger")
            logger.warning("Failed login attempt: missing username or password.")
            return render_template('login.html'), 400

        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(password):
            login_user(user)
            logger.info(f"Successful login for user '{username}'")
            flash(f"Welcome back, {user.username}!", "success")

            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard.dashboard_alias'))
        else:
            # Generic error message to prevent account enumeration
            logger.warning(f"Failed login attempt for username '{username}'")
            flash("Invalid username or password.", "danger")
            return render_template('login.html'), 400

    return render_template('login.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    if current_user.is_authenticated:
        username = current_user.username
        logout_user()
        session.clear()
        logger.info(f"User '{username}' logged out successfully.")
        flash("You have been logged out successfully.", "info")
    return redirect(url_for('auth.login'))
