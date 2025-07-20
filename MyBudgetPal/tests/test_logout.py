import pytest
import os
from unittest.mock import patch, Mock
from dotenv import load_dotenv

# Load environment variables from .env in the project root for tests
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev")
    flask_app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY', 'test_csrf')
    with flask_app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def patch_captcha():
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {'success': True, 'score': 1.0}
        mock_post.return_value = mock_response
        yield

def test_logout(client):
    # First, log in with valid credentials
    response = client.post('/signin', data={
        'username': 'asd',
        'password': 'Password123!',
        'g-recaptcha-response': 'PASSED'
    }, follow_redirects=True)
    assert b"Welcome back" in response.data
    # Now, log out
    response = client.get('/logout', follow_redirects=True)
    print(response.data.decode())  # Debug: print the response HTML
    # Check that the user is redirected to the login page or sees a logout message
    assert b"Welcome to MyBudgetPal" in response.data and b'Forgot Password?' in response.data

def test_logout_invalidates_session(client):
    # Log in
    response = client.post('/signin', data={
        'username': 'asd',
        'password': 'Password123!',
        'g-recaptcha-response': 'PASSED'
    }, follow_redirects=True)
    assert b"Welcome back, asd" in response.data

    # Log out
    response = client.get('/logout', follow_redirects=True)
    assert b"Sign In" in response.data and b"Welcome to MyBudgetPal" in response.data

    # Try to access a protected page (e.g., dashboard)
    response = client.get('/friends?', follow_redirects=True)
    # Should be redirected to login or see an unauthorized message
    assert b"Welcome to MyBudgetPal" in response.data and b"Forgot Password" in response.data
