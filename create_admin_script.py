from app import create_app
from models import db, User

app = create_app()
with app.app_context():
    existing = User.query.filter_by(username='admin').first()
    if existing:
        u = existing
    else:
        u = User(username='admin', is_active=True)
    
    u.set_password('admin123')
    db.session.add(u)
    db.session.commit()
    print('User admin created or updated successfully!')
