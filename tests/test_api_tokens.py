"""API token management tests — generate, list, revoke, Bearer auth."""
from __future__ import annotations


def _register_login(client, email, pw="TokenPass1!"):
    client.post("/api/auth/register", json={
        "name": "Token User", "email": email,
        "password": pw, "confirm_password": pw,
    })
    client.post("/api/auth/login", json={"email": email, "password": pw})


def test_create_token(client):
    _register_login(client, "tok1@example.com")
    r = client.post("/api/v2/tokens/create", json={"name": "CI", "expires_in_days": 30})
    assert r.status_code == 201
    data = r.get_json()
    assert "token" in data
    assert len(data["token"]) >= 32


def test_list_tokens(client):
    _register_login(client, "tok2@example.com")
    client.post("/api/v2/tokens/create", json={"name": "Test"})
    r = client.get("/api/v2/tokens")
    assert r.status_code == 200
    assert r.get_json()["count"] >= 1


def test_revoke_token(client):
    _register_login(client, "tok3@example.com")
    create_r = client.post("/api/v2/tokens/create", json={"name": "Revoke me"})
    # List to get the ID
    list_r = client.get("/api/v2/tokens")
    token_id = list_r.get_json()["tokens"][0]["id"]
    r = client.delete(f"/api/v2/tokens/{token_id}")
    assert r.status_code == 200
    # List again — count should be 0
    assert client.get("/api/v2/tokens").get_json()["count"] == 0


def test_bearer_token_authenticates(client):
    """Generate a Bearer token then use it without a session cookie."""
    _register_login(client, "tok4@example.com")
    token = client.post("/api/v2/tokens/create", json={"name": "Bearer"}).get_json()["token"]
    client.post("/api/auth/logout")

    # Fresh client (no session)
    from flask import current_app
    r = client.get(
        "/api/v2/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.get_json()["authenticated"] is True


def test_invalid_bearer_rejected(client):
    r = client.get(
        "/api/dashboard/stats",
        headers={"Authorization": "Bearer totally_invalid_token"},
    )
    assert r.status_code == 401


def test_expiry_validation(client):
    """Token with 0-day expiry should be rejected."""
    _register_login(client, "tok5@example.com")
    r = client.post("/api/v2/tokens/create", json={"expires_in_days": 0})
    assert r.status_code == 400
