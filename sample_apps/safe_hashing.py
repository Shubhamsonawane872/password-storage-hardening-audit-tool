from argon2 import PasswordHasher
hasher = PasswordHasher()
password_hash = hasher.hash(password)
