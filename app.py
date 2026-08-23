import os
import logging
import click
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, CSRFError
from config import Config
from models import db, User

login_manager = LoginManager()
csrf = CSRFProtect()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required directories exist (including instance)
    os.makedirs(app.config.get('INSTANCE_DIR', os.path.join(app.config['BASE_DIR'], 'instance')), exist_ok=True)
    os.makedirs(app.config['SCANS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    
    # Auto-synchronize SQLite schema changes safely
    with app.app_context():
        try:
            db.create_all()
            # Verify and add missing columns to scans table if existing DB
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            if 'scans' in inspector.get_table_names():
                existing_cols = [c['name'] for c in inspector.get_columns('scans')]
                with db.engine.connect() as conn:
                    if 'xml_path' not in existing_cols:
                        conn.execute(text("ALTER TABLE scans ADD COLUMN xml_path VARCHAR(512);"))
                    if 'error_message' not in existing_cols:
                        conn.execute(text("ALTER TABLE scans ADD COLUMN error_message TEXT;"))
                    conn.commit()
            if 'nse_results' in inspector.get_table_names():
                existing_nse_cols = [c['name'] for c in inspector.get_columns('nse_results')]
                with db.engine.connect() as conn:
                    if 'status' not in existing_nse_cols:
                        conn.execute(text("ALTER TABLE nse_results ADD COLUMN status VARCHAR(50) DEFAULT 'Completed';"))
                    if 'error_message' not in existing_nse_cols:
                        conn.execute(text("ALTER TABLE nse_results ADD COLUMN error_message TEXT;"))
                    if 'port_number' not in existing_nse_cols:
                        conn.execute(text("ALTER TABLE nse_results ADD COLUMN port_number INTEGER;"))
                    conn.commit()
            if 'findings' in inspector.get_table_names():
                existing_finding_cols = [c['name'] for c in inspector.get_columns('findings')]
                with db.engine.connect() as conn:
                    if 'rule_id' not in existing_finding_cols:
                        conn.execute(text("ALTER TABLE findings ADD COLUMN rule_id VARCHAR(50);"))
                    if 'category' not in existing_finding_cols:
                        conn.execute(text("ALTER TABLE findings ADD COLUMN category VARCHAR(100);"))
                    if 'confidence' not in existing_finding_cols:
                        conn.execute(text("ALTER TABLE findings ADD COLUMN confidence VARCHAR(50) DEFAULT 'HIGH';"))
                    if 'observation_type' not in existing_finding_cols:
                        conn.execute(text("ALTER TABLE findings ADD COLUMN observation_type VARCHAR(50) DEFAULT 'OBSERVED';"))
                    if 'remediation' not in existing_finding_cols:
                        conn.execute(text("ALTER TABLE findings ADD COLUMN remediation TEXT;"))
                    if 'status' not in existing_finding_cols:
                        conn.execute(text("ALTER TABLE findings ADD COLUMN status VARCHAR(50) DEFAULT 'OPEN';"))
                    if 'created_at' not in existing_finding_cols:
                        conn.execute(text("ALTER TABLE findings ADD COLUMN created_at DATETIME;"))
                    conn.commit()
        except Exception as dbe:
            pass

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access the security dashboard.'
    login_manager.login_message_category = 'warning'


    # Configure Logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(app.config['BASE_DIR'], 'app.log')),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    logger.info("Initializing Network Scanner application...")

    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.scans import scans_bp
    from routes.findings import findings_bp
    from routes.reports import reports_bp
    from routes.authorized_targets import authorized_targets_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(authorized_targets_bp)

    # Template Context Processors
    @app.context_processor
    def inject_system_status():
        from services.nmap_service import check_nmap_availability, get_active_scans_count
        nmap_status = check_nmap_availability(app.config.get('NMAP_PATH', 'nmap'))
        active_count = get_active_scans_count()
        return {
            'system_nmap_status': nmap_status,
            'active_scans_count': active_count
        }


    # CLI Commands
    @app.cli.command('init-db')
    def init_db_command():
        """Initialize the SQLite database and create all tables."""
        with app.app_context():
            db.create_all()
            click.echo("Database initialized successfully / tables are ready.")
            logger.info("Database tables verified/created via init-db command.")

    @app.cli.command('init-admin')
    @click.option('--username', prompt='Admin username', help='Username for administrator')
    @click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for administrator')
    def init_admin_command(username, password):
        """Create an initial administrator user account securely."""
        username = username.strip()
        if not username:
            click.echo("Username cannot be empty.")
            return

        with app.app_context():
            db.create_all()
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                click.echo(f"Administrator user '{username}' already exists.")
                return

            new_admin = User(username=username, is_active=True)
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()

            click.echo(f"Administrator '{username}' created successfully.")
            logger.info(f"Admin account created via init-admin command: {username}")

    # Security HTTP Response Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # CSP allowing required CDNs (Bootstrap, FontAwesome, Google Fonts, Chart.js) and safe inline scripts
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

    # Global Error Handlers (Hybrid JSON/HTML support)
    def _is_api_request():
        return (
            request.path.startswith('/api/') or
            request.is_json or
            (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html)
        )

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        reason = getattr(e, 'description', str(e))
        logger.warning(f"CSRF validation failed: {reason}")
        if _is_api_request():
            return {"error": "CSRF token missing or invalid."}, 400
        flash("CSRF session expired or invalid request signature. Please try again.", "danger")
        return redirect(url_for('auth.login'))

    @app.errorhandler(400)
    def bad_request(e):
        if _is_api_request():
            return {"error": "Bad Request: " + getattr(e, 'description', 'Invalid request parameters.')}, 400
        return render_template('base.html', error_message="Bad Request (400)."), 400

    @app.errorhandler(403)
    def forbidden_error(e):
        if _is_api_request():
            return {"error": "Forbidden: " + getattr(e, 'description', 'You do not have permission to access this resource.')}, 403
        return render_template('base.html', error_message="Access Forbidden (403)."), 403

    @app.errorhandler(404)
    def page_not_found(e):
        if _is_api_request():
            return {"error": "Resource not found (404)."}, 404
        return render_template('base.html', error_message="Page not found (404)."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        logger.error(f"Internal server error: {str(e)}")
        if _is_api_request():
            return {"error": "An internal server error occurred. Please contact administrator if problem persists."}, 500
        return render_template('base.html', error_message="An internal server error occurred (500). Please check the server logs."), 500

    return app

if __name__ == '__main__':
    app = create_app()
    # Bind to localhost by default for laboratory safety
    app.run(host='127.0.0.1', port=5000, debug=True)
