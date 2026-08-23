from datetime import datetime
from models import db

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False, index=True)
    scan_profile = db.Column(db.String(100), nullable=False, default='service_default_nse')
    start_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(50), default='pending', nullable=False, index=True)  # pending, running, completed, failed, timeout, cancelled
    number_of_hosts = db.Column(db.Integer, default=0)
    number_of_open_ports = db.Column(db.Integer, default=0)
    number_of_findings = db.Column(db.Integer, default=0)
    report_path = db.Column(db.String(512), nullable=True)
    xml_path = db.Column(db.String(512), nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    hosts = db.relationship('Host', backref='scan', lazy=True, cascade='all, delete-orphan')
    nse_results = db.relationship('NSEResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='scan', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target': self.target,
            'scan_profile': self.scan_profile,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': round(self.duration, 2) if self.duration else None,
            'status': self.status,
            'number_of_hosts': self.number_of_hosts,
            'number_of_open_ports': self.number_of_open_ports,
            'number_of_findings': self.number_of_findings,
            'xml_path': self.xml_path,
            'has_xml': bool(self.xml_path),
            'error_message': self.error_message
        }

    def __repr__(self):
        return f"<Scan id={self.id} target='{self.target}' status='{self.status}'>"
