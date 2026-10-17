"""Auth decorators — session-based and Bearer-token-based."""
from __future__ import annotations

import hashlib
from functools import wraps

from flask import jsonify, request, session


# ─────────────────────────────────────────────────────────────────────────────
# Internal helper: resolve identity from session OR Bearer token
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_identity() -> dict | None:
    """
    Return {'user_id': int, 'role': str} from:
      1. A valid Flask session, or
      2. An Authorization: Bearer <token> header backed by the api_tokens table.
    Returns None if neither is present / valid.
    """
    # 1 — session
    if "user_id" in session:
        return {"user_id": session["user_id"], "role": session.get("role", "user")}

    # 2 — Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        raw_token = auth_header[7:].strip()
        if raw_token:
            identity = _verify_bearer(raw_token)
            if identity:
                return identity

    return None


def _verify_bearer(raw_token: str) -> dict | None:
    """
    Hash the raw token, look it up in api_tokens, check expiry, fetch user role.
    Updates last_used_at as a side-effect.
    Returns {'user_id': int, 'role': str} or None.
    """
    from flask import current_app
    from app.db import get_db_connection

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = db.cursor()
    try:
        cursor.execute(
            """SELECT t.user_id, u.role, u.is_active
               FROM api_tokens t
               JOIN users u ON u.id = t.user_id
               WHERE t.token_hash = ?
                 AND t.expires_at > datetime('now')""",
            (token_hash,),
        )
        row = cursor.fetchone()
        if row and row["is_active"]:
            # Touch last_used_at
            cursor.execute(
                "UPDATE api_tokens SET last_used_at = datetime('now') WHERE token_hash = ?",
                (token_hash,),
            )
            db.commit()
            return {"user_id": row["user_id"], "role": row["role"]}
        return None
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Public decorators
# ─────────────────────────────────────────────────────────────────────────────

def login_required(f):
    """Allow access when the caller has an active session OR a valid Bearer token."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        identity = _resolve_identity()
        if not identity:
            return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401
        # Inject into session-like namespace so route handlers can read session['user_id']
        if "user_id" not in session:
            session["user_id"] = identity["user_id"]
            session["role"] = identity["role"]
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """Allow access only to admins (session or Bearer token with admin role)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        identity = _resolve_identity()
        if not identity:
            return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401
        if identity["role"] != "admin":
            return jsonify({"error": "Forbidden", "message": "Admin access required."}), 403
        if "user_id" not in session:
            session["user_id"] = identity["user_id"]
            session["role"] = identity["role"]
        return f(*args, **kwargs)
    return wrapper


def role_required(required_role: str):
    """Generic role gate — use admin_required for the common case."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            identity = _resolve_identity()
            if not identity:
                return jsonify({"error": "Unauthorized"}), 401
            if identity["role"] != required_role:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
