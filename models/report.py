from datetime import datetime
from models import db

class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    report_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default='COMPLETED', nullable=False)  # GENERATING, COMPLETED, FAILED
    generated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'report_id': self.report_id,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'status': self.status,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'target': self.scan.target if self.scan else None,
            'profile': self.scan.scan_profile if self.scan else None
        }

    def __repr__(self):
        return f"<Report id={self.id} report_id='{self.report_id}' status='{self.status}'>"
