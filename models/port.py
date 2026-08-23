from models import db

class Port(db.Model):
    __tablename__ = 'ports'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp', nullable=False)
    state = db.Column(db.String(20), default='open', nullable=False)
    service = db.Column(db.String(100), nullable=True)
    product = db.Column(db.String(100), nullable=True)
    version = db.Column(db.String(100), nullable=True)
    extra_info = db.Column(db.Text, nullable=True)

    # Relationships
    findings = db.relationship('Finding', backref='port', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Port id={self.id} port={self.port_number}/{self.protocol} service='{self.service}'>"
