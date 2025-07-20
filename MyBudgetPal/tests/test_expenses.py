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

def test_add_expense(client):
    # Log in first
    response = client.post('/signin', data={
        'username': 'asd',
        'password': 'Password123!',
        'g-recaptcha-response': 'PASSED'
    }, follow_redirects=True)
    assert b"Welcome back" in response.data

    # Add a new expense with correct field names and formats
    response = client.post('/add-expense', data={
        'date': '2025-07-02', 
        'amount': '25.50',
        'category': 'Food',
        'description': 'Lunch',
        'method': 'Cash',  # Correct field name
        'share_with[]': []  # No friends to share with
    }, follow_redirects=True)
    print(response.data.decode())  # Debug: print the response HTML
    # Check for success message or redirect
    assert b"Expense has been successfully updated." in response.data or b"Return to Home" in response.data


def test_add_expense_failure(client):
    # Log in first
    response = client.post('/signin', data={
        'username': 'asd',
        'password': 'Password123!',
        'g-recaptcha-response': 'PASSED'
    }, follow_redirects=True)
    assert b"Welcome back" in response.data

    # Attempt to add an expense with missing required fields (e.g., no amount)
    response = client.post('/add-expense', data={
        'date': '2025-07-02',
        'amount': '!',  # Invalid amount
        'category': 'Food',
        'description': 'Lunch',
        'method': 'Cash',
        'share_with[]': []
    }, follow_redirects=True)
    print(response.data.decode())  # Debug: print the response HTML
    # Check for error message or form re-render
    assert b"Invalid amount!" in response.data


