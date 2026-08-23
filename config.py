import os

class Config:
    # Flask application secret key for session signing
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-129837192837')
    
    # Base directory of the workspace
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
    
    # Database Configuration (SQLite)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f"sqlite:///{os.path.join(INSTANCE_DIR, 'security_dashboard.db')}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security & Form Protection Settings
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Scanning Storage Paths
    SCANS_FOLDER = os.path.join(BASE_DIR, 'scans')
    REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')
    
    # Nmap Config
    NMAP_PATH = os.environ.get('NMAP_PATH', 'nmap')
    SCAN_TIMEOUT_SECONDS = int(os.environ.get('SCAN_TIMEOUT_SECONDS', 300))
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', 1))
    NMAP_SIMULATION_FALLBACK = os.environ.get('NMAP_SIMULATION_FALLBACK', 'True').lower() in ('true', '1', 'yes')
    
    # Authorized Lab Scan Boundaries & Policies
    ALLOW_PUBLIC_SCANS = False
    ALLOW_PRIVATE_SUBNETS = True
    ALLOW_LOCALHOST = True
    ALLOWED_LAB_TARGETS = [
        '127.0.0.1',
        '::1',
        'localhost',
        '192.168.1.10',
        '192.168.1.20',
        '192.168.1.50',
        '192.168.56.20',
        '192.168.56.30',
        '10.0.0.5',
        'ubuntu-lab.local',
        'lab-server.local',
        'training-target.local'
    ]
    
    # Application Version
    APP_VERSION = "v1.0.0"
