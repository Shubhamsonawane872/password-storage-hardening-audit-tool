"""Small secure password-handling example used by scanner regression tests."""

import getpass
import os

from argon2 import PasswordHasher

hasher = PasswordHasher()


def verify_password(password: str, hashed_password: str) -> bool:
    return hasher.verify(hashed_password, password)


def main() -> None:
    password = os.environ.get("DEMO_PASSWORD") or getpass.getpass("Password: ")
    hashed_password = hasher.hash(password)
    print("Password stored securely (hashed)")
    print("Password verification:", verify_password(password, hashed_password))


if __name__ == "__main__":
    main()
