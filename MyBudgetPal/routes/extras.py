from flask import Blueprint, render_template, session
from utils.decorators import login_required
from utils.helpers import get_logged_cursor
from utils.logging_config import setup_logger, get_user_context

extras_bp = Blueprint('extras', __name__)

# Set up logging - using centralized configuration
logger = setup_logger("extras")

@extras_bp.route("/404")
def page_404():
    return render_template("404.html")

@extras_bp.route("/privacy")
@login_required
def privacy():
    return render_template("privacy.html")


@extras_bp.route("/settings")
@login_required
def settings():
    user_id, username, ip_address = get_user_context()
    
    logger.info(f"Settings page accessed by user '{username}' (ID: {user_id}) from IP {ip_address}")
    
    try:
        cursor = get_logged_cursor(dictionary=True)
        cursor.execute(
            "SELECT is_totp_enabled FROM users WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        cursor.close()
        
        totp_enabled = result.get("is_totp_enabled", False) if result else False
        
        logger.info(f"Settings loaded successfully for user '{username}' (ID: {user_id}), TOTP enabled: {totp_enabled} from IP {ip_address}")
        
        return render_template("settings.html", username=session.get("username"), totp_enabled=totp_enabled)
        
    except Exception as e:
        logger.error(f"Error loading settings for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
        if 'cursor' in locals():
            cursor.close()
        raise