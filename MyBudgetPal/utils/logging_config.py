import logging
import os
from flask import session, request

def setup_logger(logger_name, log_filename=None):
    """
    Set up a logger with consistent configuration
    
    Args:
        logger_name (str): Name for the logger (e.g., 'auth', 'expenses', 'dashboard')
        log_filename (str): Optional custom log filename, defaults to {logger_name}.log
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Use LOG_DIR environment variable - same pattern as other files
    log_dir = os.environ.get('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Use custom filename or default to logger_name.log
    if log_filename is None:
        log_filename = f"{logger_name}.log"
    
    log_path = os.path.join(log_dir, log_filename)
    
    # Configure file-based logging
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.INFO)
    
    # Formatter and Logger
    formatter = logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s')
    file_handler.setFormatter(formatter)
    
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    
    # Avoid adding multiple handlers if logger already exists
    if not logger.handlers:
        logger.addHandler(file_handler)
    
    return logger

def get_user_context():
    """Get current user context for logging"""
    try:
        user_id = session.get("user_id", "Anonymous")
        username = session.get("username", "Anonymous")
        ip_address = request.remote_addr if request else "Unknown"
        return user_id, username, ip_address
    except:
        return "Unknown", "Unknown", "Unknown"