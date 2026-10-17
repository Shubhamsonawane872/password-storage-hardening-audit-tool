"""Advanced API routes — analytics, API tokens, scheduled scans, risk analysis."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request, session

from app.analytics import ComplianceMetrics, VulnerabilityAnalytics
from app.auth.api_tokens import APITokenManager
from app.auth.decorators import admin_required, login_required
from app.scheduler import cancel_scheduled_job, list_scheduled_jobs, schedule_scan

advanced_api = Blueprint("advanced_api", __name__, url_prefix="/api/v2")


# ── Token self-verification ───────────────────────────────────────────────────

@advanced_api.route("/auth/verify", methods=["GET"])
@login_required
def verify_auth():
    """Returns the resolved identity — useful for testing Bearer tokens."""
    return jsonify({
        "authenticated": True,
        "user_id": session.get("user_id"),
        "role": session.get("role"),
    }), 200


# ── API Token management ──────────────────────────────────────────────────────

@advanced_api.route("/tokens", methods=["GET"])
@login_required
def list_api_tokens():
    tokens = APITokenManager.list_tokens(session["user_id"])
    return jsonify({"tokens": tokens, "count": len(tokens)}), 200


@advanced_api.route("/tokens/create", methods=["POST"])
@login_required
def create_api_token():
    data = request.get_json() or {}
    name = str(data.get("name", "API Token"))[:80]
    expires_in_days = int(data.get("expires_in_days", 90))
    if not 1 <= expires_in_days <= 365:
        return jsonify({"error": "expires_in_days must be 1–365"}), 400
    token = APITokenManager.generate_token(session["user_id"], name, expires_in_days)
    return jsonify({
        "token": token,
        "message": "Save this token securely — it will not be shown again.",
        "expires_in_days": expires_in_days,
    }), 201


@advanced_api.route("/tokens/<int:token_id>", methods=["DELETE"])
@login_required
def revoke_api_token(token_id: int):
    ok = APITokenManager.revoke_token(session["user_id"], token_id)
    if ok:
        return jsonify({"message": "Token revoked"}), 200
    return jsonify({"error": "Token not found"}), 404


# ── Analytics (user-scoped) ───────────────────────────────────────────────────

@advanced_api.route("/analytics/trends", methods=["GET"])
@login_required
def get_trends():
    days = int(request.args.get("days", 30))
    if not 1 <= days <= 365:
        return jsonify({"error": "days must be 1–365"}), 400
    return jsonify(VulnerabilityAnalytics.get_trend_analysis(session["user_id"], days)), 200


@advanced_api.route("/analytics/rule-distribution", methods=["GET"])
@login_required
def get_rule_distribution():
    return jsonify(VulnerabilityAnalytics.get_rule_distribution(session["user_id"])), 200


@advanced_api.route("/analytics/severity-breakdown", methods=["GET"])
@login_required
def get_severity_breakdown():
    return jsonify(VulnerabilityAnalytics.get_severity_breakdown(session["user_id"])), 200


@advanced_api.route("/analytics/vulnerable-files", methods=["GET"])
@login_required
def get_vulnerable_files():
    limit = min(int(request.args.get("limit", 10)), 50)
    files = VulnerabilityAnalytics.get_most_vulnerable_files(session["user_id"], limit)
    return jsonify({"vulnerable_files": files, "count": len(files)}), 200


@advanced_api.route("/analytics/improvement", methods=["GET"])
@login_required
def get_improvement():
    return jsonify(VulnerabilityAnalytics.get_improvement_metrics(session["user_id"])), 200


# ── Analytics (admin-scoped) ──────────────────────────────────────────────────

@advanced_api.route("/analytics/organization-score", methods=["GET"])
@admin_required
def get_org_score():
    return jsonify(ComplianceMetrics.calculate_security_score()), 200


@advanced_api.route("/analytics/compliance-report", methods=["GET"])
@admin_required
def get_compliance_report():
    return jsonify(ComplianceMetrics.get_compliance_report()), 200


# ── Scheduled scans ───────────────────────────────────────────────────────────

@advanced_api.route("/scans/schedule", methods=["POST"])
@login_required
def schedule_recurring_scan():
    data = request.get_json() or {}
    scan_id = data.get("scan_id")
    cron = data.get("schedule_time", "").strip()
    if not scan_id or not cron:
        return jsonify({"error": "scan_id and schedule_time are required"}), 400
    # Verify scan ownership
    from app.db import get_db_connection
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    row = db.execute("SELECT user_id FROM scans WHERE id=?", (scan_id,)).fetchone()
    db.close()
    if not row or row["user_id"] != session["user_id"]:
        return jsonify({"error": "Scan not found"}), 404
    job_id = schedule_scan(scan_id, session["user_id"], cron)
    if job_id:
        return jsonify({"job_id": job_id, "cron_pattern": cron}), 201
    return jsonify({"error": "Invalid cron expression or scheduler unavailable"}), 500


@advanced_api.route("/scans/scheduled", methods=["GET"])
@login_required
def list_scheduled():
    jobs = list_scheduled_jobs(session["user_id"])
    return jsonify({"scheduled_scans": jobs, "count": len(jobs)}), 200


@advanced_api.route("/scans/scheduled/<job_id>", methods=["DELETE"])
@login_required
def cancel_scheduled(job_id: str):
    jobs = list_scheduled_jobs(session["user_id"])
    if not any(j["id"] == job_id for j in jobs):
        return jsonify({"error": "Scheduled scan not found"}), 404
    ok = cancel_scheduled_job(job_id)
    return (jsonify({"message": "Cancelled"}), 200) if ok else (jsonify({"error": "Failed"}), 500)


# ── Per-scan risk analysis ────────────────────────────────────────────────────

@advanced_api.route("/scan/<int:scan_id>/risk-analysis", methods=["GET"])
@login_required
def get_risk_analysis(scan_id: int):
    from app.db import get_db_connection
    from app.scanner.ml_analyzer import VulnerabilityRiskScorer

    db = get_db_connection(current_app.config["DATABASE_PATH"])
    row = db.execute("SELECT user_id FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row or row["user_id"] != session["user_id"]:
        db.close()
        return jsonify({"error": "Scan not found"}), 404

    findings = [dict(r) for r in db.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))]
    db.close()

    scorer = VulnerabilityRiskScorer()
    scored = []
    scores = []
    for f in findings:
        s = scorer.calculate_risk_score(f)
        scores.append(s)
        scored.append({
            "finding_id": f["id"],
            "rule_id": f["rule_id"],
            "rule_title": f["rule_title"],
            "severity": f["severity"],
            "file_name": f.get("file_name"),
            "line_number": f.get("line_number"),
            "risk_score": round(s, 2),
            "confidence": f.get("confidence", 0.8),
        })

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return jsonify({
        "scan_id": scan_id,
        "findings_with_scores": scored,
        "top_risks": scored[:5],
        "average_risk": round(sum(scores) / len(scores), 2) if scores else 0.0,
    }), 200


@advanced_api.route("/scan/<int:scan_id>/comparison", methods=["POST"])
@login_required
def compare_scans(scan_id: int):
    data = request.get_json() or {}
    prev_id = data.get("compare_to_scan_id")
    if not prev_id:
        return jsonify({"error": "compare_to_scan_id is required"}), 400

    from app.db import get_db_connection
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    uid = session["user_id"]

    s1 = db.execute("SELECT user_id,total_findings,critical_count,high_count FROM scans WHERE id=?", (scan_id,)).fetchone()
    s2 = db.execute("SELECT user_id,total_findings,critical_count,high_count FROM scans WHERE id=?", (prev_id,)).fetchone()
    db.close()

    if not s1 or not s2 or s1["user_id"] != uid or s2["user_id"] != uid:
        return jsonify({"error": "Scans not found"}), 404

    delta = s1["total_findings"] - s2["total_findings"]
    return jsonify({
        "current_scan_id": scan_id,
        "previous_scan_id": prev_id,
        "current_findings": s1["total_findings"],
        "previous_findings": s2["total_findings"],
        "delta": delta,
        "critical_delta": (s1["critical_count"] or 0) - (s2["critical_count"] or 0),
        "high_delta": (s1["high_count"] or 0) - (s2["high_count"] or 0),
        "trend": "improved" if delta < 0 else ("same" if delta == 0 else "degraded"),
    }), 200
