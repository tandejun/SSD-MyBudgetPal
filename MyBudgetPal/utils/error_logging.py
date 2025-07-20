import logging
import os
from flask import session, request, render_template, redirect, url_for
from utils.logging_config import setup_logger, get_user_context

class ErrorLoggingManager:
    """Centralized error logging management"""
    
    def __init__(self):
        self.error_logger = None
        self.access_logger = None
        self.setup_logging()
    
    def setup_logging(self):
        """Setup all logging configurations using centralized logging_config"""
        # Use centralized logging setup
        self.error_logger = setup_logger("error_pages")
        self.error_logger.setLevel(logging.WARNING) 
        
        self.access_logger = setup_logger("access")
        self.access_logger.setLevel(logging.INFO) 
    
    def log_request(self):
        """Log incoming request details"""
        user_id, username, ip_address = get_user_context()
        method = request.method
        url = request.url
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        self.access_logger.info(f"REQUEST - Method: {method} | URL: {url} | User: '{username}' (ID: {user_id}) | IP: {ip_address} | User-Agent: {user_agent}")
    
    def log_response(self, response):
        """Log response details"""
        user_id, username, ip_address = get_user_context()
        method = request.method
        url = request.url
        status_code = response.status_code
        
        if status_code >= 400:
            self.error_logger.warning(f"HTTP {status_code} - Method: {method} | URL: {url} | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        else:
            self.access_logger.info(f"RESPONSE {status_code} - Method: {method} | URL: {url} | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        
        return response
    
    def handle_400_error(self, error):
        """Handle 400 Bad Request errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.warning(f"400 BAD REQUEST - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address} | Error: {str(error)}")
        
        if user_id != "Anonymous":
            return render_template("400.html"), 400
        else:
            return redirect(url_for("auth.signin")), 400

    def handle_401_error(self, error):
        """Handle 401 Unauthorized errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.warning(f"401 UNAUTHORIZED - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        return redirect(url_for("auth.signin")), 401
    
    def handle_403_error(self, error):
        """Handle 403 Forbidden errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.warning(f"403 FORBIDDEN - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        
        if user_id != "Anonymous":
            return render_template("403.html"), 403
        else:
            return redirect(url_for("auth.signin")), 403

    def handle_404_error(self, error):
        """Handle 404 Not Found errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        referrer = request.referrer or "Direct Access"
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        self.error_logger.warning(f"404 NOT FOUND - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address} | Referrer: '{referrer}' | User-Agent: {user_agent}")
        
        # Check if user is logged in to determine which template to show
        if user_id != "Anonymous":
            return render_template("404.html"), 404
        else:
            # For anonymous users, redirect to signin
            return redirect(url_for("auth.signin")), 404
        
    def handle_405_error(self, error):
        """Handle 405 Method Not Allowed errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        method = request.method
        
        self.error_logger.warning(f"405 METHOD NOT ALLOWED - Method: {method} | URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        
        if user_id != "Anonymous":
            return render_template("405.html"), 405
        else:
            return redirect(url_for("auth.signin")), 405

    def handle_413_error(self, error):
        """Handle 413 Request Entity Too Large errors (file upload size)"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.warning(f"413 REQUEST TOO LARGE - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        
        if user_id != "Anonymous":
            return render_template("413.html"), 413
        else:
            return redirect(url_for("auth.signin")), 413

    def handle_429_error(self, error):
        """Handle 429 Too Many Requests errors (rate limiting)"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.warning(f"429 TOO MANY REQUESTS - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        
        if user_id != "Anonymous":
            return render_template("429.html"), 429
        else:
            return redirect(url_for("auth.signin")), 429

    def handle_500_error(self, error):
        """Handle 500 Internal Server errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.error(f"500 INTERNAL ERROR - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address} | Error: {str(error)}")
        
        if user_id != "Anonymous":
            return render_template("500.html"), 500
        else:
            return redirect(url_for("auth.signin")), 500
    
    def handle_502_error(self, error):
        """Handle 502 Bad Gateway errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.error(f"502 BAD GATEWAY - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        
        if user_id != "Anonymous":
            return render_template("502.html"), 502
        else:
            return redirect(url_for("auth.signin")), 502

    def handle_503_error(self, error):
        """Handle 503 Service Unavailable errors"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        
        self.error_logger.error(f"503 SERVICE UNAVAILABLE - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address}")
        
        if user_id != "Anonymous":
            return render_template("503.html"), 503
        else:
            return redirect(url_for("auth.signin")), 503

    def handle_generic_error(self, error):
        """Handle any other HTTP errors not specifically handled"""
        user_id, username, ip_address = get_user_context()
        requested_url = request.url
        status_code = getattr(error, 'code', 'Unknown')
        
        self.error_logger.error(f"{status_code} GENERIC ERROR - URL: '{requested_url}' | User: '{username}' (ID: {user_id}) | IP: {ip_address} | Error: {str(error)}")
        
        if user_id != "Anonymous":
            return render_template("generic_error.html", error_code=status_code), status_code
        else:
            return redirect(url_for("auth.signin")), status_code

    def register_handlers(self, app):
        """Register all handlers with the Flask app"""
        
        # Register request/response logging
        @app.before_request
        def before_request_logging():
            self.log_request()
        
        @app.after_request
        def after_request_logging(response):
            return self.log_response(response)
        
        @app.errorhandler(400)
        def handle_400(error):
            return self.handle_400_error(error)
        
        @app.errorhandler(401)
        def handle_401(error):
            return self.handle_401_error(error)

        @app.errorhandler(403)
        def handle_403(error):
            return self.handle_403_error(error)
        
        @app.errorhandler(404)
        def handle_404(error):
            return self.handle_404_error(error)
        
        @app.errorhandler(405)
        def handle_405(error):
            return self.handle_405_error(error)
        
        @app.errorhandler(413)
        def handle_413(error):
            return self.handle_413_error(error)
        
        @app.errorhandler(429)
        def handle_429(error):
            return self.handle_429_error(error)
        
        @app.errorhandler(500)
        def handle_500(error):
            return self.handle_500_error(error)

        @app.errorhandler(502)
        def handle_502(error):
            return self.handle_502_error(error)
        
        @app.errorhandler(503)
        def handle_503(error):
            return self.handle_503_error(error)
        
        # Generic error handler for any other HTTP errors
        @app.errorhandler(Exception)
        def handle_exception(error):
            # Check if it's an HTTP error
            if hasattr(error, 'code'):
                return self.handle_generic_error(error)
            else:
                # For non-HTTP exceptions, treat as 500
                return self.handle_500_error(error)

# Create a global instance
error_logging_manager = ErrorLoggingManager()

# Convenience function for easy integration
def setup_error_logging(app):
    """Easy setup function for error logging"""
    error_logging_manager.register_handlers(app)