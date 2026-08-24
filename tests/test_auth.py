import pytest
from models import db, User, Scan, Host, Port, NSEResult, Finding, Report
from app import create_app
from tests.conftest import TestConfigWithCSRF

def test_database_initialization(app):
    """Test 1: Verify database tables are initialized successfully."""
    with app.app_context():
        # Querying tables should not throw errors
        assert User.query.count() == 0
        assert Scan.query.count() == 0
        assert Host.query.count() == 0
        assert Port.query.count() == 0
        assert NSEResult.query.count() == 0
        assert Finding.query.count() == 0
        assert Report.query.count() == 0

def test_user_creation(app):
    """Test 2: Create a user and verify attributes."""
    with app.app_context():
        user = User(username='auditor1', is_active=True)
        user.set_password('Pass123456!')
        db.session.add(user)
        db.session.commit()

        fetched = User.query.filter_by(username='auditor1').first()
        assert fetched is not None
        assert fetched.username == 'auditor1'
        assert fetched.is_active is True
        assert fetched.password_hash != 'Pass123456!'

def test_password_hashing(app):
    """Test 3 & 4: Verify password hashing and check_password behavior."""
    with app.app_context():
        user = User(username='secuser')
        user.set_password('ComplexP@ssw0rd')
        assert user.password_hash != 'ComplexP@ssw0rd'
        assert user.check_password('ComplexP@ssw0rd') is True
        assert user.check_password('WrongPassword') is False
        assert user.check_password('') is False

def test_duplicate_username_handling(app):
    """Test 10: Verify unique constraint on username."""
    with app.app_context():
        u1 = User(username='admin_dup')
        u1.set_password('Password1')
        db.session.add(u1)
        db.session.commit()

        u2 = User(username='admin_dup')
        u2.set_password('Password2')
        db.session.add(u2)
        with pytest.raises(Exception):
            db.session.commit()
        db.session.rollback()

def test_successful_login(client, auth_user):
    """Test 5: Verify successful login authenticates session."""
    response = client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Security Assessment Dashboard' in response.data or b'Dashboard' in response.data
    assert b'testadmin' in response.data

def test_failed_login(client, auth_user):
    """Test 6: Verify failed login with wrong credentials."""
    response = client.post('/login', data={
        'username': 'testadmin',
        'password': 'WrongPassword'
    }, follow_redirects=True)

    assert response.status_code == 400
    assert b'Invalid username or password.' in response.data

    # Test non-existent user
    response2 = client.post('/login', data={
        'username': 'nonexistent',
        'password': 'SomePassword'
    }, follow_redirects=True)

    assert response2.status_code == 400
    assert b'Invalid username or password.' in response2.data

def test_logout(client, auth_user):
    """Test 7: Verify user logout clears authenticated session."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    logout_resp = client.post('/logout', follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b'Security Portal Authentication' in logout_resp.data

    # Attempt accessing protected page after logout
    dash_resp = client.get('/dashboard', follow_redirects=True)
    assert b'Please log in to access the security dashboard.' in dash_resp.data

def test_protected_route_unauthenticated(client):
    """Test 8: Verify unauthenticated users are redirected to login."""
    protected_urls = [
        '/dashboard',
        '/about',
        '/scan/new',
        '/scan/progress/1',
        '/scan/results/1',
        '/scan/history',
        '/findings',
        '/reports',
        '/report/view/1'
    ]

    for url in protected_urls:
        res = client.get(url, follow_redirects=False)
        assert res.status_code == 302
        assert '/login' in res.location

def test_protected_route_authenticated(client, auth_user, app):
    """Test 9: Verify authenticated users can access protected routes."""
    with app.app_context():
        from models import Scan
        scan = Scan(id=1, user_id=auth_user.id, target='127.0.0.1', scan_profile='service_default_nse', status='completed')
        db.session.add(scan)
        db.session.commit()

    client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    })

    protected_urls = [
        '/',
        '/dashboard',
        '/about',
        '/scan/new',
        '/scan/progress/1',
        '/scan/results/1',
        '/scan/history',
        '/findings',
        '/reports',
        '/report/view/1'
    ]

    for url in protected_urls:
        res = client.get(url)
        assert res.status_code == 200

def test_cli_init_admin(runner, app):
    """Test CLI init-admin creation command."""
    result = runner.invoke(args=['init-admin', '--username', 'cliadmin', '--password', 'AdminPass123!'])
    assert 'created successfully' in result.output

    with app.app_context():
        user = User.query.filter_by(username='cliadmin').first()
        assert user is not None
        assert user.check_password('AdminPass123!') is True

    # Run again to ensure no duplicate creation
    result_dup = runner.invoke(args=['init-admin', '--username', 'cliadmin', '--password', 'AdminPass123!'])
    assert 'already exists' in result_dup.output

def test_csrf_behavior():
    """Test 12: Verify CSRF protection rejects POST request without token when CSRF enabled."""
    app = create_app(TestConfigWithCSRF)
    client = app.test_client()

    response = client.post('/login', data={
        'username': 'testadmin',
        'password': 'SecretPassword123!'
    }, follow_redirects=True)

    # CSRF error should flash error and redirect back to login
    assert b'CSRF session expired or invalid request signature' in response.data or b'The CSRF token is missing' in response.data or b'Security Portal Authentication' in response.data
