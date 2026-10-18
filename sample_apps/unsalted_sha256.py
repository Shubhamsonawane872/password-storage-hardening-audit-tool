import hashlib
def store_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
