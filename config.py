import os
from datetime import timedelta


class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        # For development only - will raise error in production
        SECRET_KEY = 'dev-key-change-in-production-12345'

    # Security
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # File upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    # Database
    DATABASE = 'diary.db'
    DIARY_DIR = 'diaries'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True  # Enable in production


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development


# Use appropriate config based on environment
if os.environ.get('FLASK_ENV') == 'production':
    app_config = ProductionConfig()
else:
    app_config = DevelopmentConfig()