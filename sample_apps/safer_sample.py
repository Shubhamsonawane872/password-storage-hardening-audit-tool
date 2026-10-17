"""
SAFER SAMPLE CODE - BEST PRACTICES
This code demonstrates secure password handling practices.
"""

# BEST PRACTICE: Using Argon2id for password hashing
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class SecureUserManager:
    """Secure user management with Argon2id"""
    
    def __init__(self):
        self.users = {}
        self.ph = PasswordHasher()
    
    def hash_password(self, password):
        """Hash password using Argon2id"""
        return self.ph.hash(password)
    
    def verify_password(self, password_hash, password):
        """Verify password against hash"""
        try:
            self.ph.verify(password_hash, password)
            return True
        except VerifyMismatchError:
            return False
    
    def register_user(self, username, password):
        """Register user with hashed password"""
        # Password is hashed before storage
        password_hash = self.hash_password(password)
        self.users[username] = password_hash
        return True
    
    def authenticate(self, username, password):
        """Authenticate user securely"""
        stored_hash = self.users.get(username)
        if not stored_hash:
            return False
        
        return self.verify_password(stored_hash, password)


# BEST PRACTICE: Using bcrypt alternative
import bcrypt

def hash_with_bcrypt(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)


def verify_with_bcrypt(password_hash, password):
    """Verify password with bcrypt"""
    return bcrypt.checkpw(password.encode(), password_hash)


# BEST PRACTICE: Using scrypt (Python 3.6+)
import hashlib
import os

def hash_with_scrypt(password):
    """Hash password using scrypt"""
    salt = os.urandom(32)
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)


# BEST PRACTICE: Using environment variables for secrets
import os

API_KEY = os.getenv('API_KEY')  # SAFE: Load from environment
DATABASE_PASSWORD = os.getenv('DB_PASSWORD')  # SAFE: Load from environment

if not API_KEY or not DATABASE_PASSWORD:
    raise ValueError("Missing required environment variables")


# BEST PRACTICE: Secure configuration
class SecureConfig:
    """Configuration loaded from environment variables"""
    
    @staticmethod
    def get_db_credentials():
        """Get database credentials from environment"""
        return {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME')
        }
    
    @staticmethod
    def get_api_keys():
        """Get API keys from environment"""
        return {
            'api_key': os.getenv('API_KEY'),
            'api_secret': os.getenv('API_SECRET'),
            'auth_token': os.getenv('AUTH_TOKEN')
        }


# BEST PRACTICE: PBKDF2 (if using Django or similar)
import hashlib
import os
import binascii

def hash_with_pbkdf2(password):
    """Hash password using PBKDF2"""
    salt = binascii.hexlify(os.urandom(32)).decode()
    iterations = 100000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${binascii.hexlify(dk).decode()}"
