"""Security-focused tests — hashing, policy, route protection."""
from __future__ import annotations

import pytest

from app.auth.utils import hash_password, validate_password, verify_password


# ── Password hashing ──────────────────────────────────────────────────────────

def test_argon2_hashes_are_unique():
    """Same plaintext → different hashes (salt is random per call)."""
    pw = "SamePass1!"
    h1 = hash_password(pw)
    h2 = hash_password(pw)
    assert h1 != h2


def test_argon2_verify_correct():
    pw = "CorrectPass1!"
    assert verify_password(hash_password(pw), pw) is True


def test_argon2_verify_wrong():
    pw = "RightPass1!"
    assert verify_password(hash_password(pw), "WrongPass1!") is False


def test_password_not_stored_plaintext(app, client):
    """
    After registration the DB row must contain a hash — never the raw password.
    Uses the shared temp-file DB so the direct SQL query sees the same data.
    """
    client.post("/api/auth/register", json={
        "name": "Mallory",
        "email": "mallory@example.com",
        "password": "MalloryPass1!",
        "confirm_password": "MalloryPass1!",
    })

    from app.db import get_db_connection
    db = get_db_connection(app.config["DATABASE_PATH"])
    row = db.execute(
        "SELECT password_hash FROM users WHERE email=?",
        ("mallory@example.com",),
    ).fetchone()
    db.close()

    assert row is not None, "User was not inserted"
    stored = row["password_hash"]
    assert stored != "MalloryPass1!", "Password stored in plaintext!"
    # Argon2id hashes begin with $argon2id$
    assert stored.startswith("$argon2"), f"Unexpected hash format: {stored[:30]}"


# ── Password policy ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("pw,fragment", [
    ("short",        "at least"),
    ("alllowercase1!", "uppercase"),
    ("ALLUPPERCASE1!", "lowercase"),
    ("NoDigitsHere!",  "digit"),
    ("NoSpecial123",   "special"),
])
def test_password_policy_rejects(pw, fragment):
    valid, msg = validate_password(pw)
    assert not valid
    assert fragment.lower() in msg.lower()


def test_password_policy_accepts():
    valid, _ = validate_password("ValidPass1!")
    assert valid


# ── Route protection ──────────────────────────────────────────────────────────

def test_dashboard_requires_auth(client):
    r = client.get("/api/dashboard/stats")
    assert r.status_code == 401


def test_scanner_upload_requires_auth(client):
    r = client.post("/api/scanner/upload", data={})
    assert r.status_code == 401


def test_admin_route_blocks_regular_user(client):
    client.post("/api/auth/register", json={
        "name": "Regular", "email": "regular@example.com",
        "password": "RegularPass1!", "confirm_password": "RegularPass1!",
    })
    client.post("/api/auth/login", json={
        "email": "regular@example.com", "password": "RegularPass1!",
    })
    r = client.get("/api/admin/users")
    assert r.status_code == 403


def test_admin_route_allows_admin(admin_client):
    r = admin_client.get("/api/admin/users")
    assert r.status_code == 200
    assert "users" in r.get_json()
