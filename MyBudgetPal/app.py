from flask import Flask, session, redirect, url_for, flash, request
from dotenv import load_dotenv
from config import Config
from extensions import bcrypt
from utils.helpers import close_db, get_db
from utils.logging_config import setup_logger, get_user_context
import logging
import os
from utils.session_tracker import track_session_activity
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from utils.error_logging import setup_error_logging

# Import blueprints
from routes.auth import auth_bp
from routes.categories import categories_bp
from routes.dashboard import dashboard_bp
from routes.expenses import expenses_bp
from routes.extras import extras_bp
from routes.friends import friends_bp
from routes.receipts import receipts_bp
import datetime
import hashlib

load_dotenv()  # This will load variables from the .env file into environment

# Set up logging for app
logger = setup_logger("app")

# Basic logging setup
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config.from_object(Config)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB
# Prevent JavaScript access to session cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Ensures cookies are only sent over HTTPS
app.config['SESSION_COOKIE_SECURE'] = True
# Prevents session cookies from being sent with cross-site requests
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
csrf = CSRFProtect(app)
bcrypt.init_app(app)

logger.info("Flask application initialized with security configurations")

# Setup error logging
setup_error_logging(app)
logger.info("Error logging setup completed")

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(categories_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(expenses_bp)
app.register_blueprint(extras_bp)
app.register_blueprint(friends_bp)
app.register_blueprint(receipts_bp)

logger.info("All blueprints registered successfully")

def get_user_context():
    """Get current user context for logging"""
    try:
        user_id = session.get("user_id", "Anonymous")
        username = session.get("username", "Anonymous")
        ip_address = request.remote_addr if request else "Unknown"
        return user_id, username, ip_address
    except:
        return "Unknown", "Unknown", "Unknown"

# Track session activity on every request
@app.before_request
def before_request():
    # Only track activity for authenticated users
    if session.get("user_id") and session.get("db_session_id"):
        user_id, username, ip_address = get_user_context()
        db_session_id = session.get("db_session_id")
        
        logger.info(f"Session validation started for user '{username}' (ID: {user_id}), session ID: {db_session_id} from IP {ip_address}")
        
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "SELECT expires_at, hashed_token FROM session WHERE session_id = %s AND is_active = TRUE",
                (db_session_id,)
            )
            result = cursor.fetchone()  # (expires_at, hashed_token)

            ''' Validate session_token against hashed_token, which Flask should have it covered already to prevent tampering
            When Flask detects tampering, it will clear the session and logout so the code below is more for if
            the cookie is decoded and re-signed 
            '''
            session_token = session.get("session_token")
            if not session_token or not result or not result[1]:
                # No session token or no session record: force logout
                cursor.close()
                session.clear()
                logger.warning(f"Session token missing or session not found for user '{username}' (ID: {user_id}), session ID: {db_session_id} from IP {ip_address}")
                flash("Session invalid. Please log in again.", "warning")
                return redirect(url_for("auth.signin"))
                
            hashed_token = hashlib.sha256(session_token.encode()).hexdigest()
            if hashed_token != result[1]:
                # Token mismatch: possible hijack or tampering
                logger.error(f"Session token mismatch detected for user '{username}' (ID: {user_id}), session ID: {db_session_id} from IP {ip_address} - possible tampering")
                cursor.execute(
                    "UPDATE session SET is_active = FALSE WHERE session_id = %s",
                    (db_session_id,),
                )
                db.commit()
                cursor.close()
                session.clear()
                flash("Session invalid or tampered. Please log in again.", "danger")
                return redirect(url_for("auth.signin"))

            # Check expiry
            expires_at = result[0]
            if expires_at and expires_at < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
                # Session expired: log out user
                logger.warning(f"Session expired for user '{username}' (ID: {user_id}), session ID: {db_session_id}, expired at: {expires_at} from IP {ip_address}")
                cursor.execute(
                    "UPDATE session SET is_active = FALSE WHERE session_id = %s",
                    (db_session_id,),
                )
                db.commit()
                cursor.close()
                session.clear()
                flash("Session expired due to inactivity. Please log in again.", "warning")
                return redirect(url_for("auth.signin"))
                
            cursor.close()
            logger.info(f"Session validation successful for user '{username}' (ID: {user_id}), session ID: {db_session_id} from IP {ip_address}")
            track_session_activity()
            
        except Exception as e:
            logger.error(f"Session validation error for user '{username}' (ID: {user_id}), session ID: {db_session_id}: {str(e)} from IP {ip_address}")
            if 'cursor' in locals():
                cursor.close()
            session.clear()
            flash("Session error. Please log in again.", "danger")
            return redirect(url_for("auth.signin"))

@app.teardown_appcontext
def teardown_db(exception):
    if exception:
        logger.error(f"Database teardown with exception: {str(exception)}")
    close_db(exception)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    user_id, username, ip_address = get_user_context()
    
    logger.warning(f"CSRF error for user '{username}' (ID: {user_id}) from IP {ip_address}: {e.description}")
    flash("Validation failed: " + e.description, "danger")
    return "Validation failed: " + e.description, 400

# Set Security headers for all responses
@app.after_request
def set_security_headers(response):
    user_id, username, ip_address = get_user_context()
    
    # Log security headers being set (only for non-static files to avoid spam)
    if not request.endpoint or not request.endpoint.startswith('static'):
        logger.info(f"Security headers set for user '{username}' (ID: {user_id}) accessing {request.endpoint} from IP {ip_address}")
    
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn-uicons.flaticon.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn-uicons.flaticon.com; "
        "connect-src 'self' https://www.google.com; "
        "frame-src https://www.google.com; "
        "img-src 'self' data:; "
        "object-src 'none';"
    )

    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers["X-Frame-Options"] = "DENY"
    response.headers['Permissions-Policy'] = (
        'geolocation=(), camera=(), microphone=(), autoplay=(), usb=(), serial=()'
    )
    return response

if __name__ == "__main__":
    logger.info("Starting Flask application in debug mode on host 0.0.0.0:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)