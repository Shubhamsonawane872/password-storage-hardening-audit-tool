"""
Pytest configuration and shared fixtures.

Key design decisions
--------------------
* Every test gets a FRESH in-memory SQLite database wired directly into the
  app via TestingConfig.  No fixture writes to a separate connection — all
  writes go through the same app.test_client() so that the in-memory DB is
  the same object the Flask request context sees.
* The admin_client fixture promotes a user to admin by calling the app's own
  database helper (get_db_connection) with the path the app actually uses,
  which is ':memory:' in TestingConfig.  Because SQLite in-memory databases
  are per-connection, we store the DB path on the app config and patch it to
  a real temp file so all connections share state.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

from app import create_app
from app.config import TestingConfig
from app.db import create_schema        # ← re-use the real schema builder


# ── App / client fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def app():
    """
    Create a fresh Flask app wired to a real (but temporary) SQLite file.
    Using a file instead of ':memory:' means every connection inside the
    app sees the same data — which is essential for the admin-promotion
    trick in admin_client and for the password-hash verification test.
    """
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    class _TestCfg(TestingConfig):
        DATABASE_PATH = db_path
        TESTING = True
        WTF_CSRF_ENABLED = False
        SECRET_KEY = "test-secret-key"

    flask_app = create_app(_TestCfg)

    # Schema is created inside create_app → init_db, but let's be explicit
    with flask_app.app_context():
        from app.db import get_db_connection
        conn = get_db_connection(db_path)
        # Only create if tables are missing (init_db may have already run)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cur.fetchone():
            create_schema(cur)
            conn.commit()
        conn.close()

    yield flask_app

    # Teardown: delete the temp DB file
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture(scope="function")
def client(app):
    """Plain test client — no session."""
    return app.test_client()


@pytest.fixture(scope="function")
def runner(app):
    return app.test_cli_runner()


# ── Authenticated-user fixtures ───────────────────────────────────────────────

@pytest.fixture(scope="function")
def auth_client(client):
    """
    Test client with a logged-in regular user.
    The client object itself carries the session cookie.
    """
    client.post("/api/auth/register", json={
        "name": "Test User",
        "email": "testuser@example.com",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!",
    })
    client.post("/api/auth/login", json={
        "email": "testuser@example.com",
        "password": "TestPass123!",
    })
    return client


@pytest.fixture(scope="function")
def admin_client(app, client):
    """
    Test client with a logged-in admin user.

    Strategy:
      1. Register the user through the API (goes into the real temp DB).
      2. Directly UPDATE the role in the same temp DB file.
      3. Log in — the session will carry role='admin'.
    """
    client.post("/api/auth/register", json={
        "name": "Admin User",
        "email": "adminuser@example.com",
        "password": "AdminPass123!",
        "confirm_password": "AdminPass123!",
    })

    # Promote to admin by writing directly to the shared temp DB file
    db_path = app.config["DATABASE_PATH"]
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE users SET role='admin' WHERE email=?",
        ("adminuser@example.com",),
    )
    conn.commit()
    conn.close()

    # Log in — the server will load role='admin' from the DB
    resp = client.post("/api/auth/login", json={
        "email": "adminuser@example.com",
        "password": "AdminPass123!",
    })
    assert resp.status_code == 200, f"Admin login failed: {resp.get_json()}"
    return client


# ── Helpers exposed to tests ──────────────────────────────────────────────────

def register_and_login(client, email: str, password: str = "TestPass123!",
                       name: str = "User") -> None:
    """Convenience: register + login in one call."""
    client.post("/api/auth/register", json={
        "name": name, "email": email,
        "password": password, "confirm_password": password,
    })
    client.post("/api/auth/login", json={"email": email, "password": password})
