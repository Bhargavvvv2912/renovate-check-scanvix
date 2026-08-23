from models import db

class NSEResult(db.Model):
    __tablename__ = 'nse_results'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=True, index=True)
    script_id = db.Column(db.String(100), nullable=False)
    service = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    output = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='info', nullable=False)  # info, low, medium, high, critical
    status = db.Column(db.String(50), default='Completed', nullable=False)  # Pending, Running, Completed, Failed, Skipped
    error_message = db.Column(db.Text, nullable=True)
    port_number = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f"<NSEResult id={self.id} script='{self.script_id}' status='{self.status}' severity='{self.severity}'>"
