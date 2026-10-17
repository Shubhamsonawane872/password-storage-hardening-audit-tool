"""Authorization / IDOR / RBAC tests."""
from __future__ import annotations

from tests.conftest import register_and_login


def test_unauthenticated_blocked_on_all_protected_routes(client):
    for method, path in [
        ("GET",    "/api/dashboard/stats"),
        ("GET",    "/api/scanner/scans"),
        ("GET",    "/api/admin/users"),
        ("GET",    "/api/v2/analytics/trends"),
    ]:
        r = getattr(client, method.lower())(path)
        assert r.status_code == 401, f"{method} {path} should be 401, got {r.status_code}"


def test_user_cannot_view_other_users_scan(app, client):
    """IDOR: user B must not be able to read user A's scan by guessing scan_id."""
    # User A uploads a scan (we simulate by inserting directly)
    import sqlite3, os
    db_path = app.config["DATABASE_PATH"]

    # Register user A, log in, get their id
    client.post("/api/auth/register", json={
        "name": "Alice", "email": "alice_idor@example.com",
        "password": "AlicePass1!", "confirm_password": "AlicePass1!",
    })
    client.post("/api/auth/login", json={
        "email": "alice_idor@example.com", "password": "AlicePass1!",
    })

    # Insert a scan for user A directly in the DB
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    alice_id = conn.execute(
        "SELECT id FROM users WHERE email=?", ("alice_idor@example.com",)
    ).fetchone()["id"]
    conn.execute(
        "INSERT INTO scans (user_id, original_filename, scan_status) VALUES (?,?,?)",
        (alice_id, "alice_secret.py", "completed"),
    )
    conn.commit()
    alice_scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    # Log out
    client.post("/api/auth/logout")

    # Register user B and log in
    client.post("/api/auth/register", json={
        "name": "Bob", "email": "bob_idor@example.com",
        "password": "BobPass1!", "confirm_password": "BobPass1!",
    })
    client.post("/api/auth/login", json={
        "email": "bob_idor@example.com", "password": "BobPass1!",
    })

    # Bob tries to read Alice's scan
    r = client.get(f"/api/scanner/scan/{alice_scan_id}")
    assert r.status_code == 404, "User B should get 404 for User A's scan"


def test_user_cannot_delete_other_users_scan(app, client):
    """IDOR: user B must not be able to delete user A's scan."""
    import sqlite3
    db_path = app.config["DATABASE_PATH"]

    client.post("/api/auth/register", json={
        "name": "Alice2", "email": "alice2_idor@example.com",
        "password": "Alice2Pass1!", "confirm_password": "Alice2Pass1!",
    })
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    alice_id = conn.execute(
        "SELECT id FROM users WHERE email=?", ("alice2_idor@example.com",)
    ).fetchone()["id"]
    conn.execute(
        "INSERT INTO scans (user_id, original_filename, scan_status) VALUES (?,?,?)",
        (alice_id, "alice2_secret.py", "completed"),
    )
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    # Log in as Bob
    client.post("/api/auth/register", json={
        "name": "Bob2", "email": "bob2_idor@example.com",
        "password": "Bob2Pass1!", "confirm_password": "Bob2Pass1!",
    })
    client.post("/api/auth/login", json={
        "email": "bob2_idor@example.com", "password": "Bob2Pass1!",
    })
    r = client.delete(f"/api/scanner/scan/{scan_id}")
    assert r.status_code == 404


def test_regular_user_cannot_access_admin_endpoints(client):
    client.post("/api/auth/register", json={
        "name": "Normal", "email": "normal@example.com",
        "password": "NormalPass1!", "confirm_password": "NormalPass1!",
    })
    client.post("/api/auth/login", json={
        "email": "normal@example.com", "password": "NormalPass1!",
    })
    for path in ["/api/admin/users", "/api/admin/stats", "/api/v2/analytics/organization-score"]:
        r = client.get(path)
        assert r.status_code == 403, f"{path} should be 403 for regular user"


def test_admin_can_access_admin_endpoints(admin_client):
    for path in ["/api/admin/users", "/api/admin/stats"]:
        r = admin_client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"


def test_logout_invalidates_session(client):
    client.post("/api/auth/register", json={
        "name": "Session", "email": "session@example.com",
        "password": "SessionPass1!", "confirm_password": "SessionPass1!",
    })
    client.post("/api/auth/login", json={
        "email": "session@example.com", "password": "SessionPass1!",
    })
    # Confirm logged in
    assert client.get("/api/auth/me").status_code == 200
    # Log out
    client.post("/api/auth/logout")
    # Now protected route must reject
    assert client.get("/api/dashboard/stats").status_code == 401
