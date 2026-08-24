"""
ScanVix Public Landing Page Blueprint.

Serves the public, unauthenticated landing/overview page at '/'.
This is a purely informational page — no database queries, Nmap execution,
or private data access occurs here.
"""
import logging
from flask import Blueprint, render_template
from flask_login import current_user

logger = logging.getLogger(__name__)

landing_bp = Blueprint('landing', __name__)


@landing_bp.route('/')
def index():
    """
    Render the public ScanVix landing page.

    This route is intentionally NOT protected by @login_required.
    It serves static educational content and a 3D visualization.
    The template receives only the authentication state so it can
    show 'Launch ScanVix' vs 'Sign In' buttons appropriately.
    """
    is_authenticated = current_user.is_authenticated if current_user else False
    return render_template('landing.html', is_authenticated=is_authenticated)
