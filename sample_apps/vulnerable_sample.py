"""
VULNERABLE SAMPLE CODE - FOR TESTING ONLY
This code contains intentional security vulnerabilities for scanner testing.
DO NOT USE IN PRODUCTION!
"""

# VULNERABILITY: PWD001 - Plaintext password storage
def insecure_login(username, password):
    """Insecure login - passwords stored in plaintext"""
    users_database = {
        'admin': 'AdminPassword123',  # VULNERABLE: plaintext password
        'user': 'UserPassword456'      # VULNERABLE: plaintext password
    }
    return users_database.get(username) == password


# VULNERABILITY: PWD002 - MD5 hashing
import hashlib

def store_password_md5(password):
    """VULNERABLE: Using MD5 to hash passwords"""
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY: PWD003 - SHA1 hashing
def store_password_sha1(password):
    """VULNERABLE: Using SHA1 to hash passwords"""
    return hashlib.sha1(password.encode()).hexdigest()


# VULNERABILITY: PWD004 - Hardcoded credentials
API_KEY = "sk_test_REDACTED"                      # VULNERABLE: hardcoded secret
DATABASE_PASSWORD = "prod_db_password_12345"     # VULNERABLE: hardcoded secret


# VULNERABILITY: PWD005 - Unsalted hashing
def store_password_unsalted(password):
    """VULNERABLE: SHA256 without salt"""
    return hashlib.sha256(password.encode()).hexdigest()


# VULNERABILITY: PWD001 - Direct password storage in config
CONFIG = {
    'database_user': 'admin',
    'database_password': 'secretPassword123',  # VULNERABLE
    'api_token': 'token_xyz789'                # VULNERABLE
}


# Example of what NOT to do
class UserManager:
    """VULNERABLE: Insecure user management"""
    
    def __init__(self):
        self.users = {}
    
    def register_user(self, username, password):
        # VULNERABLE: storing password directly
        self.users[username] = password
        return True
    
    def authenticate(self, username, password):
        # VULNERABLE: comparing plaintext passwords
        return self.users.get(username) == password
