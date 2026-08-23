from datetime import datetime
from models import db

class AuthorizedTarget(db.Model):
    __tablename__ = 'authorized_targets'

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False, unique=True)
    target_type = db.Column(db.String(50), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('authorized_targets', lazy=True))

    def __repr__(self):
        return f'<AuthorizedTarget {self.target} ({self.target_type})>'
