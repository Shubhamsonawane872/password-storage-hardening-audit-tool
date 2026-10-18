import hashlib
def store_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
