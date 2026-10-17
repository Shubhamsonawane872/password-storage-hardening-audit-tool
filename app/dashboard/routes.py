"""Dashboard stats endpoint."""
from flask import Blueprint, current_app, jsonify, session

from app.auth.decorators import login_required
from app.db import get_db_connection

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/stats", methods=["GET"])
@login_required
def get_stats():
    user_id = session["user_id"]
    db = get_db_connection(current_app.config["DATABASE_PATH"])

    row = db.execute(
        """SELECT
             COUNT(*)                    AS total_scans,
             SUM(total_findings)         AS total_findings,
             SUM(COALESCE(critical_count,0)) AS critical_count,
             SUM(high_count)             AS high_count,
             SUM(medium_count)           AS medium_count,
             SUM(low_count)              AS low_count,
             SUM(info_count)             AS info_count
           FROM scans
           WHERE user_id=? AND scan_status='completed'""",
        (user_id,),
    ).fetchone()

    recent = db.execute(
        """SELECT id, original_filename, scan_status, total_files_scanned,
                  total_findings, COALESCE(critical_count,0) AS critical_count,
                  high_count, medium_count, low_count, info_count,
                  security_score, security_grade, created_at
           FROM scans
           WHERE user_id=?
           ORDER BY created_at DESC
           LIMIT 10""",
        (user_id,),
    ).fetchall()
    db.close()

    return jsonify({
        "stats": {
            "total_scans":    row["total_scans"]    or 0,
            "total_findings": row["total_findings"] or 0,
            "critical_count": row["critical_count"] or 0,
            "high_count":     row["high_count"]     or 0,
            "medium_count":   row["medium_count"]   or 0,
            "low_count":      row["low_count"]      or 0,
            "info_count":     row["info_count"]     or 0,
        },
        "recent_scans": [dict(r) for r in recent],
    }), 200
