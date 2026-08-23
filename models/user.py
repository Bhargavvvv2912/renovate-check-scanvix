from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from models import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password: str) -> None:
        """Hash and set the user password using Werkzeug's default PBKDF2/scrypt algorithm."""
        if not password or not isinstance(password, str):
            raise ValueError("Password must be a non-empty string.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check password against the stored password hash."""
        if not password or not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User id={self.id} username='{self.username}'>"
