"""
Session activity tracking utilities
"""
import datetime
import logging
import os
from flask import session, request, g
from functools import wraps
from utils.helpers import get_db
from utils.logging_config import setup_logger, get_user_context

# Set up logging
logger = setup_logger("session_tracker")

def track_session_activity():
    """
    Update last_activity_at and expires_at for the current session
    Call this function on every authenticated request
    """
    if session.get("db_session_id") and session.get("user_id"):
        user_id = session.get("user_id")
        username = session.get("username", "Unknown")
        db_session_id = session.get("db_session_id")
        ip_address = request.remote_addr if request else "Unknown"
        
        logger.info(f"Session activity update for user '{username}' (ID: {user_id}), session ID: {db_session_id} from IP {ip_address}")
        
        try:
            db = get_db()
            if db:
                cursor = db.cursor()
                timeout_minutes = 15  # Set session timeout to 15 minutes
                now = datetime.datetime.now(datetime.timezone.utc)
                new_expires_at = now + datetime.timedelta(minutes=timeout_minutes)
                cursor.execute(
                    "UPDATE session SET last_activity_at = %s, expires_at = %s WHERE session_id = %s AND is_active = TRUE",
                    (now, new_expires_at, session.get("db_session_id"))
                )
                db.commit()
                cursor.close()
                
                logger.info(f"Session activity updated successfully for user '{username}' (ID: {user_id}), new expiry: {new_expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')} from IP {ip_address}")
                
        except Exception as e:
            logger.error(f"Session activity tracking error for user '{username}' (ID: {user_id}), session ID: {db_session_id}: {str(e)} from IP {ip_address}")
            # Log error but don't break the request
            print(f"Session activity tracking error: {e}")

def track_activity(f):
    """
    Decorator to automatically track session activity
    Usage: @track_activity above route functions
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id", "Anonymous")
        username = session.get("username", "Anonymous")
        endpoint = request.endpoint if request else "Unknown"
        ip_address = request.remote_addr if request else "Unknown"
        
        logger.info(f"Activity tracking triggered for user '{username}' (ID: {user_id}), endpoint: {endpoint} from IP {ip_address}")
        
        track_session_activity()
        return f(*args, **kwargs)
    return decorated_function