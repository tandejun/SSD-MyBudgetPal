import time
from functools import wraps
from flask import session, request, g
import mysql.connector
from utils.logging_config import setup_logger, get_user_context

# Set up logging using centralized configuration
db_logger = setup_logger("database_operations")

class DatabaseLogger:
    def __init__(self, original_cursor):
        self.cursor = original_cursor
        self.query_count = 0
        
    def execute(self, query, params=None):
        """Log and execute database query"""
        user_id, username, ip_address = get_user_context()
        
        # Sanitize query for logging (replace sensitive data)
        safe_query = self._sanitize_query(query, params)
        
        # Log the query attempt
        db_logger.info(f"QUERY ATTEMPT - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Query: {safe_query}")
        
        start_time = time.time()
        try:
            result = self.cursor.execute(query, params)
            execution_time = time.time() - start_time
            
            # Log successful execution
            db_logger.info(f"QUERY SUCCESS - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Time: {execution_time:.3f}s")
            
            # Log slow queries (>1 second)
            if execution_time > 1.0:
                db_logger.warning(f"SLOW QUERY - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Time: {execution_time:.3f}s - Query: {safe_query}")
            
            self.query_count += 1
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            db_logger.error(f"QUERY FAILED - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Time: {execution_time:.3f}s - Error: {str(e)} - Query: {safe_query}")
            raise
    
    def _sanitize_query(self, query, params):
        """Sanitize query for logging"""
        # Remove sensitive patterns
        sensitive_patterns = ['password', 'hash', 'token', 'secret']
        safe_query = query
        
        if params:
            # Replace actual parameters with placeholders
            safe_query = query.replace('%s', '[PARAM]')
            # Log parameter count but not values
            param_count = len(params) if isinstance(params, (list, tuple)) else 1
            safe_query += f" [PARAMS: {param_count}]"
        
        return safe_query[:500]  # Limit length
    
    def fetchone(self):
        user_id, username, ip_address = get_user_context()
        try:
            result = self.cursor.fetchone()
            if result:
                db_logger.info(f"FETCH ONE - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Record found")
            else:
                db_logger.info(f"FETCH ONE - User: '{username}' (ID: {user_id}) - IP: {ip_address} - No record found")
            return result
        except Exception as e:
            db_logger.error(f"FETCH ONE FAILED - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Error: {str(e)}")
            raise
    
    def fetchall(self):
        user_id, username, ip_address = get_user_context()
        try:
            result = self.cursor.fetchall()
            count = len(result) if result else 0
            db_logger.info(f"FETCH ALL - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Records: {count}")
            return result
        except Exception as e:
            db_logger.error(f"FETCH ALL FAILED - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Error: {str(e)}")
            raise
    
    def commit(self):
        user_id, username, ip_address = get_user_context()
        try:
            result = self.cursor.commit()
            db_logger.info(f"COMMIT - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Queries committed: {self.query_count}")
            self.query_count = 0
            return result
        except Exception as e:
            db_logger.error(f"COMMIT FAILED - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Error: {str(e)}")
            raise
    
    def rollback(self):
        user_id, username, ip_address = get_user_context()
        db_logger.warning(f"ROLLBACK - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Transaction rolled back")
        return self.cursor.rollback()
    
    def close(self):
        user_id, username, ip_address = get_user_context()
        db_logger.info(f"CURSOR CLOSED - User: '{username}' (ID: {user_id}) - IP: {ip_address}")
        return self.cursor.close()
    
    def __getattr__(self, name):
        return getattr(self.cursor, name)

def log_connection_attempt():
    """Log database connection attempts"""
    user_id, username, ip_address = get_user_context()
    db_logger.info(f"DB CONNECTION ATTEMPT - User: '{username}' (ID: {user_id}) - IP: {ip_address}")

def log_connection_success():
    """Log successful database connections"""
    user_id, username, ip_address = get_user_context()
    db_logger.info(f"DB CONNECTION SUCCESS - User: '{username}' (ID: {user_id}) - IP: {ip_address}")

def log_connection_failure(error):
    """Log failed database connections"""
    user_id, username, ip_address = get_user_context()
    db_logger.error(f"DB CONNECTION FAILED - User: '{username}' (ID: {user_id}) - IP: {ip_address} - Error: {str(error)}")