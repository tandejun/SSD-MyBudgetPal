import pytest
import os
from unittest.mock import patch, Mock
# Load environment variables from .env in the project root for tests
from dotenv import load_dotenv

# Adjust the path to the .env file if needed
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    flask_app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev")
    flask_app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY', 'test_csrf')  # Add this line for CSRF key
    with flask_app.test_client() as client:
        yield client

# Patch requests.post for CAPTCHA for tests
@pytest.fixture(autouse=True)
def patch_captcha():
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {'success': True, 'score': 1.0}
        mock_post.return_value = mock_response
        yield 

def test_login_page_loads(client):
    response = client.get('/signin')
    assert response.status_code == 200
    assert b"Sign In" in response.data

def test_login_invalid_user(client):
    response = client.post('/signin', data={
        'username': 'invaliduser',
        'password': 'test123!',
        'g-recaptcha-response': 'PASSED'  # Mock 
    }, follow_redirects=True)
    print(response.data.decode())  # Debug: print the response HTML
    assert b"Invalid email or password" in response.data

def test_login_valid_user(client):
    # Replace these credentials with a real test user in your database
    response = client.post('/signin', data={
        'username': 'asd',
        'password': 'Password123!',
        'g-recaptcha-response': 'PASSED'  # Mock
    }, follow_redirects=True)
    print(response.data.decode())  # Debug: print the response HTML
    # Adjust the assertion below to match what a successful login returns in your app
    assert b"Welcome back" in response.data
    assert b"Friends" in response.data
