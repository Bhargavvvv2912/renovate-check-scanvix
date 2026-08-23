from models import db

class Host(db.Model):
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255), nullable=True)
    state = db.Column(db.String(50), default='up', nullable=False)
    os_information = db.Column(db.String(255), nullable=True)

    # Relationships
    ports = db.relationship('Port', backref='host', lazy=True, cascade='all, delete-orphan')
    nse_results = db.relationship('NSEResult', backref='host', lazy=True, cascade='all, delete-orphan')
    findings = db.relationship('Finding', backref='host', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Host id={self.id} ip='{self.ip_address}' state='{self.state}'>"
