from datetime import datetime
from models import db

class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    port_id = db.Column(db.Integer, db.ForeignKey('ports.id'), nullable=True, index=True)
    rule_id = db.Column(db.String(50), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), default='info', nullable=False, index=True)  # info, low, medium, high, critical
    description = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    classification = db.Column(db.String(50), default='Observed', nullable=False)  # Observed, Potential
    confidence = db.Column(db.String(50), default='HIGH', nullable=False)  # HIGH, MEDIUM, LOW
    observation_type = db.Column(db.String(50), default='OBSERVED', nullable=False)  # OBSERVED, POTENTIAL
    status = db.Column(db.String(50), default='OPEN', nullable=False)  # OPEN, ACKNOWLEDGED, RESOLVED
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'host_id': self.host_id,
            'port_id': self.port_id,
            'rule_id': self.rule_id,
            'category': self.category,
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'remediation': self.remediation or self.recommendation,
            'classification': self.classification,
            'confidence': self.confidence,
            'observation_type': self.observation_type,
            'status': self.status,
            'host_ip': self.host.ip_address if self.host else None,
            'hostname': self.host.hostname if self.host else None,
            'port_info': f"{self.port.port_number}/{self.port.protocol}" if self.port else "—",
            'service': self.port.service if self.port else "—",
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<Finding id={self.id} title='{self.title}' severity='{self.severity}' classification='{self.classification}'>"
