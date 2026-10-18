"""Scanner routes — upload, scan, list, detail, delete."""
from __future__ import annotations

import os
import shutil
import tempfile

from flask import Blueprint, current_app, jsonify, request, session

from app.auth.decorators import login_required
from app.db import get_db_connection
from app.scanner.file_handler import FileHandler
from app.scanner.patterns import CodeScanner
from app.scanner.rules import get_rule
from app.scoring import ComprehensiveScorer

scanner_bp = Blueprint("scanner", __name__, url_prefix="/api/scanner")

_file_handler = FileHandler()
_code_scanner = CodeScanner()
_scorer = ComprehensiveScorer()


# ── Upload & Scan ─────────────────────────────────────────────────────────────

@scanner_bp.route("/upload", methods=["POST"])
@login_required
def upload_scan():
    """Upload a source file or ZIP archive and run a full security scan."""
    user_id = session["user_id"]

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "No file selected"}), 400

    ok, msg = _file_handler.validate_file(uploaded.filename)
    if not ok:
        return jsonify({"error": msg}), 400

    ok, msg = _file_handler.validate_file_size(uploaded)
    if not ok:
        return jsonify({"error": msg}), 400

    db = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = db.cursor()

    safe_name = os.path.basename(uploaded.filename)
    cursor.execute(
        "INSERT INTO scans (user_id, original_filename, scan_status) VALUES (?,?,'in_progress')",
        (user_id, safe_name),
    )
    db.commit()
    scan_id = cursor.lastrowid

    temp_dir: str | None = None
    temp_files: list[str] = []

    try:
        # ── Save upload to a dedicated temp directory ────────────────────────
        temp_dir = tempfile.mkdtemp(prefix="audit_")
        temp_main = os.path.join(temp_dir, safe_name)
        uploaded.save(temp_main)

        if safe_name.lower().endswith(".zip"):
            ok, msg, extracted = _file_handler.extract_zip_safe(temp_main, destination=temp_dir)
            if not ok:
                raise ValueError(msg)
            temp_files.extend(extracted)
        else:
            temp_files.append(temp_main)

        # ── Scan every supported file ─────────────────────────────────────────
        all_findings: list[dict] = []
        files_scanned = 0

        for filepath in temp_files:
            if not os.path.isfile(filepath):
                continue
            if not FileHandler.is_supported_file(filepath):
                continue

            ok, content = FileHandler.read_file_safe(filepath)
            if not ok:
                raise ValueError(f"Could not scan {os.path.basename(filepath)}: {content}")

            if not content.strip():
                continue

            files_scanned += 1
            fname = os.path.basename(filepath)

            raw = _code_scanner.scan_file(fname, content)

            for finding in raw:
                finding["file_name"] = fname
                finding["in_test_context"] = False
            all_findings.extend(raw)

        if files_scanned == 0:
            raise ValueError("No readable supported source files were found to scan")

        # ── Count severities (separate critical vs high) ──────────────────────
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            rule = get_rule(f["rule_id"])
            sev = f.get("severity", rule["severity"] if rule else "low")
            counts[sev] = counts.get(sev, 0) + 1

        # ── Prepare findings for comprehensive scoring ──────────────────────────
        scoring_findings = []
        for f in all_findings:
            rule = get_rule(f["rule_id"]) or {}
            scoring_findings.append({
                "rule_id": f["rule_id"],
                "severity": f.get("severity", rule.get("severity", "low")),
                "confidence": f.get("confidence", 0.8),
                "file_name": f.get("file_name", "unknown"),
                "context": {
                    "in_authentication": "auth" in f.get("file_name", "").lower(),
                    "in_test": f.get("in_test_context", False),
                }
            })
        
        # ── Use comprehensive scoring system ─────────────────────────────────
        scoring_report = _scorer.score_all(scoring_findings)
        primary_score = scoring_report["scan_summary"]["overall_score"]
        grade = scoring_report["scan_summary"]["grade"]

        # ── Persist scan record ───────────────────────────────────────────────
        cursor.execute(
            """UPDATE scans
               SET scan_status='completed',
                   total_files_scanned=?,
                   total_findings=?,
                   critical_count=?,
                   high_count=?,
                   medium_count=?,
                   low_count=?,
                   info_count=?,
                   security_score=?,
                   security_grade=?,
                   completed_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                files_scanned,
                len(all_findings),
                counts["critical"],
                counts["high"],
                counts["medium"],
                counts["low"],
                counts["info"],
                primary_score,
                grade,
                scan_id,
            ),
        )

        # ── Persist findings ──────────────────────────────────────────────────
        for f in all_findings:
            rule = get_rule(f["rule_id"]) or {}
            cursor.execute(
                """INSERT INTO findings
                     (scan_id, rule_id, rule_title, severity,
                      file_name, line_number, evidence, description,
                      recommendation, confidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    f["rule_id"],
                    rule.get("title", f["rule_id"]),
                    f.get("severity", rule.get("severity", "low")),
                    f.get("file_name"),
                    f.get("line_number"),
                    f.get("evidence", ""),
                    rule.get("description", ""),
                    rule.get("recommendation", ""),
                    f.get("confidence", 0.8),
                ),
            )

        db.commit()

        cursor.execute(
            "INSERT INTO audit_logs (user_id,action,resource_type,resource_id,status) VALUES (?,?,?,?,'success')",
            (user_id, "scan_completed", "scan", scan_id),
        )
        db.commit()

    except Exception as exc:
        cursor.execute(
            "UPDATE scans SET scan_status='failed', error_message=? WHERE id=?",
            (str(exc), scan_id),
        )
        cursor.execute(
            "INSERT INTO audit_logs (user_id,action,resource_type,resource_id,status,details) VALUES (?,?,?,?,'failure',?)",
            (user_id, "scan_failed", "scan", scan_id, str(exc)),
        )
        db.commit()
        db.close()
        status_code = 400 if isinstance(exc, ValueError) else 500
        return jsonify({"error": "Scan failed", "detail": str(exc)}), status_code

    finally:
        # ── Always delete the entire temp directory ───────────────────────────
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        db.close()

    return jsonify(
        {
            "message": "Scan completed",
            "scan_id": scan_id,
            "files_scanned": files_scanned,
            "findings": len(all_findings),
            "security_score": primary_score,
            "security_grade": grade,
            "scoring_details": {
                "algorithms_used": list(scoring_report["algorithm_results"].keys()),
                "assessment": scoring_report["scan_summary"]["assessment"],
            },
            "recommendations": scoring_report.get("recommendations", [])[:3]  # Top 3
        }
    ), 200


# ── Get scan detail ────────────────────────────────────────────────────────────

@scanner_bp.route("/scan/<int:scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id: int):
    user_id = session["user_id"]
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = db.cursor()

    cursor.execute("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
    scan = cursor.fetchone()
    if not scan:
        db.close()
        return jsonify({"error": "Scan not found"}), 404

    # Optional client-side pagination
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    offset = (page - 1) * per_page

    severity_filter = request.args.get("severity", "")
    rule_filter = request.args.get("rule_id", "")

    query = "SELECT * FROM findings WHERE scan_id=?"
    params: list = [scan_id]

    if severity_filter:
        query += " AND severity=?"
        params.append(severity_filter)
    if rule_filter:
        query += " AND rule_id=?"
        params.append(rule_filter)

    query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, line_number ASC"

    cursor.execute(query + " LIMIT ? OFFSET ?", params + [per_page, offset])
    findings = [dict(r) for r in cursor.fetchall()]

    cursor.execute(query.replace("*", "COUNT(*)"), params)
    total_findings = cursor.fetchone()[0]

    db.close()

    return jsonify(
        {
            "scan": dict(scan),
            "findings": findings,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_findings,
                "pages": max(1, -(-total_findings // per_page)),
            },
        }
    ), 200


# ── List scans (paginated) ─────────────────────────────────────────────────────

@scanner_bp.route("/scans", methods=["GET"])
@login_required
def list_scans():
    user_id = session["user_id"]
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    offset = (page - 1) * per_page

    db = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = db.cursor()

    cursor.execute(
        """SELECT id, original_filename, scan_status, total_files_scanned,
                  total_findings, critical_count, high_count, medium_count,
                  low_count, info_count, security_score, security_grade,
                  created_at, completed_at
           FROM scans
           WHERE user_id=?
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?""",
        (user_id, per_page, offset),
    )
    scans = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id=?", (user_id,))
    total = cursor.fetchone()[0]
    db.close()

    return jsonify(
        {
            "scans": scans,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": max(1, -(-total // per_page)),
            },
        }
    ), 200


# ── Delete scan ────────────────────────────────────────────────────────────────

@scanner_bp.route("/scan/<int:scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id: int):
    user_id = session["user_id"]
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = db.cursor()

    cursor.execute("SELECT user_id FROM scans WHERE id=?", (scan_id,))
    row = cursor.fetchone()
    if not row or row["user_id"] != user_id:
        db.close()
        return jsonify({"error": "Scan not found"}), 404

    cursor.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    cursor.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    db.commit()

    cursor.execute(
        "INSERT INTO audit_logs (user_id,action,resource_type,resource_id,status) VALUES (?,?,?,?,'success')",
        (user_id, "scan_deleted", "scan", scan_id),
    )
    db.commit()
    db.close()
    return jsonify({"message": "Scan deleted"}), 200


# ── Rules reference ────────────────────────────────────────────────────────────

@scanner_bp.route("/rules", methods=["GET"])
@login_required
def list_rules():
    """Return the full rule registry for display in the UI."""
    from app.scanner.rules import get_all_rules
    return jsonify({"rules": get_all_rules()}), 200


# ── Detailed scoring breakdown ─────────────────────────────────────────────────

@scanner_bp.route("/scan/<int:scan_id>/scoring-breakdown", methods=["GET"])
@login_required
def get_scoring_breakdown(scan_id: int):
    """Get detailed scoring breakdown using multiple algorithms"""
    user_id = session["user_id"]
    db = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = db.cursor()
    
    # Get scan and findings
    cursor.execute("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
    scan = cursor.fetchone()
    if not scan:
        db.close()
        return jsonify({"error": "Scan not found"}), 404
    
    cursor.execute(
        """SELECT id, rule_id, severity, confidence, file_name, line_number, evidence
           FROM findings WHERE scan_id=?
           ORDER BY CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                    ELSE 5 END""",
        (scan_id,)
    )
    findings_rows = cursor.fetchall()
    db.close()
    
    # Prepare findings for scoring
    findings = []
    for row in findings_rows:
        findings.append({
            "rule_id": row["rule_id"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "file_name": row["file_name"],
            "context": {
                "in_authentication": "auth" in row["file_name"].lower() if row["file_name"] else False,
                "in_test": False,
            }
        })
    
    # Generate comprehensive scoring report
    scoring_report = _scorer.score_all(findings)
    
    return jsonify(scoring_report), 200
