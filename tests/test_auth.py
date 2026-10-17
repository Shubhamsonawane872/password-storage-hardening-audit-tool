"""Authentication route tests."""
from __future__ import annotations


# ── Registration ──────────────────────────────────────────────────────────────

def test_register_success(client):
    r = client.post("/api/auth/register", json={
        "name": "Alice Smith",
        "email": "alice@example.com",
        "password": "AlicePass1!",
        "confirm_password": "AlicePass1!",
    })
    assert r.status_code == 201
    assert "message" in r.get_json()


def test_register_duplicate_email(client):
    payload = {
        "name": "Bob", "email": "bob@example.com",
        "password": "BobPass1!", "confirm_password": "BobPass1!",
    }
    client.post("/api/auth/register", json=payload)
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code == 409
    assert "already" in r.get_json()["error"].lower()


def test_register_password_mismatch(client):
    r = client.post("/api/auth/register", json={
        "name": "Carol", "email": "carol@example.com",
        "password": "Carol1Pass!", "confirm_password": "Different1!",
    })
    assert r.status_code == 400
    assert "match" in r.get_json()["error"].lower()


def test_register_weak_password(client):
    r = client.post("/api/auth/register", json={
        "name": "Dave", "email": "dave@example.com",
        "password": "short", "confirm_password": "short",
    })
    assert r.status_code == 400


def test_register_missing_name(client):
    r = client.post("/api/auth/register", json={
        "name": "", "email": "eve@example.com",
        "password": "EvePass1!", "confirm_password": "EvePass1!",
    })
    assert r.status_code == 400


def test_register_invalid_email(client):
    r = client.post("/api/auth/register", json={
        "name": "Frank", "email": "not-an-email",
        "password": "FrankPass1!", "confirm_password": "FrankPass1!",
    })
    assert r.status_code == 400


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_success(client):
    client.post("/api/auth/register", json={
        "name": "Grace", "email": "grace@example.com",
        "password": "GracePass1!", "confirm_password": "GracePass1!",
    })
    r = client.post("/api/auth/login", json={
        "email": "grace@example.com", "password": "GracePass1!",
    })
    assert r.status_code == 200
    data = r.get_json()
    assert "user" in data
    assert data["user"]["email"] == "grace@example.com"


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={
        "name": "Heidi", "email": "heidi@example.com",
        "password": "HeidiPass1!", "confirm_password": "HeidiPass1!",
    })
    r = client.post("/api/auth/login", json={
        "email": "heidi@example.com", "password": "WrongPass1!",
    })
    assert r.status_code == 401
    assert "Invalid" in r.get_json()["error"]


def test_login_nonexistent_user(client):
    r = client.post("/api/auth/login", json={
        "email": "nobody@example.com", "password": "Nobody1!",
    })
    assert r.status_code == 401
    # Generic message — no account-enumeration leak
    assert "Invalid" in r.get_json()["error"]


def test_login_missing_fields(client):
    r = client.post("/api/auth/login", json={})
    assert r.status_code == 400


# ── Logout ────────────────────────────────────────────────────────────────────

def test_logout(client):
    client.post("/api/auth/register", json={
        "name": "Ivan", "email": "ivan@example.com",
        "password": "IvanPass1!", "confirm_password": "IvanPass1!",
    })
    client.post("/api/auth/login", json={
        "email": "ivan@example.com", "password": "IvanPass1!",
    })
    r = client.post("/api/auth/logout")
    assert r.status_code == 200

    # After logout, /me should return 401
    r2 = client.get("/api/auth/me")
    assert r2.status_code == 401


def test_get_current_user_logged_in(client):
    client.post("/api/auth/register", json={
        "name": "Judy", "email": "judy@example.com",
        "password": "JudyPass1!", "confirm_password": "JudyPass1!",
    })
    client.post("/api/auth/login", json={
        "email": "judy@example.com", "password": "JudyPass1!",
    })
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.get_json()["user"]["email"] == "judy@example.com"


def test_get_current_user_unauthenticated(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401
