"""Authentication utilities"""
import re
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError


# Password hasher instance
ph = PasswordHasher()

# Password policy constants
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def hash_password(password):
    """Hash a password using Argon2id"""
    return ph.hash(password)


def verify_password(password_hash, password):
    """Verify a password against its hash"""
    try:
        ph.verify(password_hash, password)
        return True
    except (VerifyMismatchError, VerificationError):
        return False


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """
    Validate password against policy:
    - Minimum 8 characters
    - Maximum 128 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must not exceed {MAX_PASSWORD_LENGTH} characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*()_+=\-\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"


def validate_name(name):
    """Validate user name"""
    if not name or not isinstance(name, str):
        return False, "Name is required"
    
    name = name.strip()
    if len(name) < 2:
        return False, "Name must be at least 2 characters"
    
    if len(name) > 100:
        return False, "Name must not exceed 100 characters"
    
    # Allow letters, spaces, hyphens, apostrophes
    if not re.match(r"^[a-zA-Z\s'\-]+$", name):
        return False, "Name contains invalid characters"
    
    return True, "Name is valid"
