"""Configuration management for the Password Audit Tool"""
import os
from datetime import timedelta

# Load environment variables
from dotenv import load_dotenv
load_dotenv()


class Config:
    """Base configuration"""
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = False
    
    # Session
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 3600)))
    
    # Database
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'instance/password_audit.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    
    # File upload
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 10485760))  # 10MB
    MAX_ZIP_SIZE = int(os.getenv('MAX_ZIP_SIZE', 52428800))    # 50MB
    MAX_FILES_IN_ZIP = int(os.getenv('MAX_FILES_IN_ZIP', 100))
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'instance/uploads')
    
    # Create upload folder if it doesn't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Rate limiting
    LOGIN_RATE_LIMIT_ATTEMPTS = int(os.getenv('LOGIN_RATE_LIMIT_ATTEMPTS', 5))
    LOGIN_RATE_LIMIT_WINDOW = int(os.getenv('LOGIN_RATE_LIMIT_WINDOW', 300))  # 5 minutes
    
    # Supported file extensions
    SUPPORTED_EXTENSIONS = {'.py', '.js', '.java', '.php', '.zip'}


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DATABASE_PATH = ':memory:'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False  # Disable CSRF in tests for simplicity


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Strict'


def get_config():
    """Get the appropriate config class based on environment"""
    env = os.getenv('FLASK_ENV', 'development')
    if env == 'production':
        return ProductionConfig
    elif env == 'testing':
        return TestingConfig
    else:
        return DevelopmentConfig
