from flask import g, current_app, session, request, url_for
import mysql.connector
import os
import logging
from utils.db_logger import DatabaseLogger, log_connection_attempt, log_connection_success, log_connection_failure
from utils.logging_config import setup_logger, get_user_context
import datetime
import logging

# Set up logging
logger = setup_logger("helpers")

def get_user_context():
    """Get current user context for logging"""
    try:
        user_id = session.get("user_id", "Anonymous")
        username = session.get("username", "Anonymous")
        ip_address = request.remote_addr if request else "Unknown"
        return user_id, username, ip_address
    except:
        return "Unknown", "Unknown", "Unknown"

def get_db():
    """Get database connection with comprehensive logging"""
    if "db" not in g:
        log_connection_attempt()
        try:
            g.db = mysql.connector.connect(
                host=os.getenv("MYSQL_HOST"),
                user=os.getenv("MYSQL_USER"),
                password=os.getenv("MYSQL_PASSWORD"),
                database=os.getenv("MYSQL_DB_NAME"),
                port=int(os.getenv("MYSQL_PORT", 3306)),
            )
            log_connection_success()
        except mysql.connector.Error as err:
            log_connection_failure(err)
            g.db = None
            raise
    return g.db

def close_db(exception):
    """Close database connection with logging"""
    db = g.pop("db", None)
    if db is not None:
        from utils.db_logger import get_user_context, db_logger
        user_id, username, ip_address = get_user_context()
        db_logger.info(f"DB CONNECTION CLOSED - User: '{username}' (ID: {user_id}) - IP: {ip_address}")
        db.close()

def load_categories(userid):
    user_id, username, ip_address = get_user_context()
    
    logger.info(f"Loading categories for user '{username}' (ID: {userid}) from IP {ip_address}")
    
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """SELECT DISTINCT(category), type FROM categories WHERE (type = 'Default' AND user_id IS NULL) OR (type = 'Custom' AND user_id = %s) ORDER BY FIELD(type, 'Default', 'Custom'), category ASC""",
            (userid,),
        )
        userCategories = cursor.fetchall()
        cursor.close()
        
        logger.info(f"Categories loaded successfully for user '{username}' (ID: {userid}): {len(userCategories)} categories from IP {ip_address}")
        
        return userCategories
    except Exception as e:
        logger.error(f"Error loading categories for user '{username}' (ID: {userid}): {str(e)} from IP {ip_address}")
        raise

def load_custom_categories(userid):
    user_id, username, ip_address = get_user_context()
    
    logger.info(f"Loading custom categories for user '{username}' (ID: {userid}) from IP {ip_address}")
    
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """SELECT DISTINCT(category), type, category_id FROM categories WHERE (type = 'Custom' AND user_id = %s) ORDER BY FIELD(type, 'Default', 'Custom'), category""",
            (userid,),
        )
        userCategories = cursor.fetchall()
        cursor.close()
        
        logger.info(f"Custom categories loaded successfully for user '{username}' (ID: {userid}): {len(userCategories)} categories from IP {ip_address}")
        
        return userCategories
    except Exception as e:
        logger.error(f"Error loading custom categories for user '{username}' (ID: {userid}): {str(e)} from IP {ip_address}")
        raise

def get_progress_color(index):
    colors = [
        "bg-orange-500", "bg-amber-500", "bg-yellow-500", "bg-lime-500",
        "bg-green-500", "bg-cyan-500", "bg-stone-500", "bg-blue-500",
        "bg-purple-500", "bg-pink-500",
    ]
    return colors[index % len(colors)]

def get_week_range(year, week):
    import datetime
    jan_1 = datetime.date(year, 1, 1)
    first_monday = jan_1 + datetime.timedelta(days=(7 - jan_1.weekday()) % 7)
    week_start = first_monday + datetime.timedelta(weeks=week - 1)
    week_end = week_start + datetime.timedelta(days=6)
    return f"{week_start.strftime('%b %d')} - {week_end.strftime('%b %d')}"

def calculate_change(current, previous):
    if previous == 0:
        return 100.0 if current > 0 else 0.0
    return round(((current - previous) / previous) * 100, 2)

def load_common_passwords(filepath=None):
    if filepath is None:
        # Always resolve from project root
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath = os.path.join(base_dir, 'data', 'xato-net-10-million-passwords-100000.txt')
    logger.info(f"Loading common passwords from file: {filepath}")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            passwords = set(line.strip() for line in f if line.strip())
        logger.info(f"Common passwords loaded successfully: {len(passwords)} passwords from file {filepath}")
        return passwords
    except Exception as e:
        logger.error(f"Error loading common passwords from {filepath}: {str(e)}")
        raise

def get_logged_cursor(dictionary=False):
    """Get a database cursor with comprehensive logging"""
    user_id, username, ip_address = get_user_context()
    
    logger.info(f"Creating logged cursor for user '{username}' (ID: {user_id}), dictionary={dictionary} from IP {ip_address}")
    
    try:
        db = get_db()
        if db is None:
            logger.error(f"Database connection failed for user '{username}' (ID: {user_id}) from IP {ip_address}")
            raise Exception("Database connection failed")
        
        cursor = db.cursor(dictionary=dictionary)
        logger.info(f"Logged cursor created successfully for user '{username}' (ID: {user_id}) from IP {ip_address}")
        
        return DatabaseLogger(cursor)
    except Exception as e:
        logger.error(f"Error creating logged cursor for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
        raise

def check_2fa_status(user_id):
    """Check if user has 2FA enabled and return notification data"""
    try:
        logger.info(f"DEBUG: Starting 2FA check for user {user_id}")
        
        db = get_db()
        cursor = db.cursor(dictionary=True)
        
        # Check if user exists and get their data (removed created_at)
        cursor.execute(
            "SELECT user_id, username, is_totp_enabled FROM users WHERE user_id = %s", 
            (user_id,)
        )
        user_data = cursor.fetchone()
        cursor.close()
        
        logger.info(f"DEBUG: Database query result for user {user_id}: {user_data}")
        
        if not user_data:
            logger.warning(f"DEBUG: No user found with ID {user_id}")
            return {"show_2fa_notification": False}
        
        # Check if is_totp_enabled column exists and get its value
        is_2fa_enabled = user_data.get("is_totp_enabled")
        
        logger.info(f"DEBUG: User {user_id} - is_totp_enabled: {is_2fa_enabled}")
        
        # If column doesn't exist or is None, assume 2FA is not enabled
        if is_2fa_enabled is None:
            logger.info(f"DEBUG: is_totp_enabled is None for user {user_id}, assuming 2FA not enabled")
            is_2fa_enabled = False
        
        # Show notification if 2FA is not enabled (removed account age check)
        if not is_2fa_enabled:
            logger.info(f"DEBUG: SHOWING 2FA notification for user {user_id}")
            return {
                "show_2fa_notification": True,
                "notification_type": "security",
                "notification_message": "Enhance your account security by enabling Two-Factor Authentication (2FA)",
                "notification_action_url": "/settings",  # Using simple URL for now
                "notification_action_text": "Enable 2FA Now"
            }
        else:
            logger.info(f"DEBUG: NOT showing 2FA notification for user {user_id} - 2FA enabled: {is_2fa_enabled}")
            return {"show_2fa_notification": False}
        
    except Exception as e:
        logger.error(f"DEBUG: Error checking 2FA status for user {user_id}: {e}")
        import traceback
        logger.error(f"DEBUG: Traceback: {traceback.format_exc()}")
        return {"show_2fa_notification": False}