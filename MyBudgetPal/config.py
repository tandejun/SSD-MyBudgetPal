import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev")
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY')
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

    # Database settings
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DB_NAME = os.getenv("MYSQL_DB_NAME", "mybudgetpal")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))

    # Google API Key or other third-party keys
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
    RECAPTCHA_SITE_KEY = os.getenv("GOOGLE_SITE_KEY", "")
    RECAPTCHA_SECRET_KEY = os.getenv("GOOGLE_SECRET_KEY", "")

    MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY')
    MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN', 'budget@mail.bobbylab.com')

# Usage in app.py:
# app.config.from_object(Config)
