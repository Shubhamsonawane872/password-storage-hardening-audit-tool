"""Profile and settings API routes."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request, session

from app.auth.decorators import login_required
from app.auth.utils import hash_password, validate_password, verify_password
from app.db import get_db_connection

profile_bp = Blueprint("profile", __name__, url_prefix="/api/profile")


@profile_bp.route("", methods=["GET"])
@login_required
def get_profile():
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    row = db.execute(
        "SELECT id,name,email,role,created_at,theme,notify_email FROM users WHERE id=?",
        (session["user_id"],),
    ).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": dict(row)}), 200


@profile_bp.route("/update", methods=["POST"])
@login_required
def update_profile():
    data = request.get_json() or {}
    uid  = session["user_id"]

    name = data.get("name", "").strip()
    if name:
        if len(name) < 2 or len(name) > 100:
            return jsonify({"error": "Name must be 2–100 characters"}), 400
        import re
        if not re.match(r"^[a-zA-Z\s'\-]+$", name):
            return jsonify({"error": "Name contains invalid characters"}), 400

    db = get_db_connection(current_app.config["DATABASE_PATH"])
    if name:
        db.execute(
            "UPDATE users SET name=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (name, uid),
        )
        session["name"] = name

    db.commit()
    db.close()
    return jsonify({"message": "Profile updated"}), 200


@profile_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json() or {}
    current_pw  = data.get("current_password", "")
    new_pw      = data.get("new_password", "")
    confirm_pw  = data.get("confirm_password", "")

    if not current_pw or not new_pw:
        return jsonify({"error": "All password fields are required"}), 400

    if new_pw != confirm_pw:
        return jsonify({"error": "New passwords do not match"}), 400

    ok, msg = validate_password(new_pw)
    if not ok:
        return jsonify({"error": msg}), 400

    db = get_db_connection(current_app.config["DATABASE_PATH"])
    row = db.execute(
        "SELECT password_hash FROM users WHERE id=?", (session["user_id"],)
    ).fetchone()

    if not row or not verify_password(row["password_hash"], current_pw):
        db.close()
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = hash_password(new_pw)
    db.execute(
        "UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (new_hash, session["user_id"]),
    )
    db.execute(
        "INSERT INTO audit_logs (user_id,action,resource_type,status) VALUES (?,?,?,?)",
        (session["user_id"], "password_changed", "user", "success"),
    )
    db.commit()
    db.close()
    return jsonify({"message": "Password changed successfully"}), 200


@profile_bp.route("/settings", methods=["POST"])
@login_required
def update_settings():
    """Persist theme preference and notification flag."""
    data = request.get_json() or {}
    theme        = data.get("theme", "light")
    notify_email = 1 if data.get("notify_email", True) else 0

    if theme not in ("light", "dark"):
        return jsonify({"error": "Invalid theme value"}), 400

    db = get_db_connection(current_app.config["DATABASE_PATH"])
    db.execute(
        "UPDATE users SET theme=?, notify_email=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (theme, notify_email, session["user_id"]),
    )
    db.commit()
    db.close()
    return jsonify({"message": "Settings saved"}), 200


@profile_bp.route("/delete", methods=["DELETE"])
@login_required
def delete_account():
    uid = session["user_id"]
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    db.execute("DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE user_id=?)", (uid,))
    db.execute("DELETE FROM scans WHERE user_id=?", (uid,))
    db.execute("DELETE FROM api_tokens WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    db.close()
    session.clear()
    return jsonify({"message": "Account deleted"}), 200
