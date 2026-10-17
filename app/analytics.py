"""Advanced analytics and insights for audit data."""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta

from flask import current_app

from app.db import get_db_connection


class VulnerabilityAnalytics:
    """Generate insights and analytics on vulnerabilities."""

    @staticmethod
    def get_trend_analysis(user_id: int | None = None, days: int = 30) -> dict:
        """Daily scan/findings counts over the past *days* days."""
        db = get_db_connection(current_app.config["DATABASE_PATH"])
        cursor = db.cursor()
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        if user_id:
            cursor.execute(
                """SELECT DATE(created_at) as date,
                          COUNT(*) as scan_count,
                          SUM(total_findings) as findings_count
                   FROM scans
                   WHERE user_id = ? AND created_at > ?
                   GROUP BY DATE(created_at)
                   ORDER BY date""",
                (user_id, cutoff),
            )
        else:
            cursor.execute(
                """SELECT DATE(created_at) as date,
                          COUNT(*) as scan_count,
                          SUM(total_findings) as findings_count
                   FROM scans
                   WHERE created_at > ?
                   GROUP BY DATE(created_at)
                   ORDER BY date""",
                (cutoff,),
            )

        trends = [
            {"date": r["date"], "scans": r["scan_count"], "findings": r["findings_count"] or 0}
            for r in cursor.fetchall()
        ]
        db.close()

        return {
            "period_days": days,
            "trends": trends,
            "total_scans": sum(t["scans"] for t in trends),
            "total_findings": sum(t["findings"] for t in trends),
        }

    @staticmethod
    def get_rule_distribution(user_id: int | None = None) -> dict:
        db = get_db_connection(current_app.config["DATABASE_PATH"])
        cursor = db.cursor()

        if user_id:
            cursor.execute(
                """SELECT f.rule_id, f.rule_title, f.severity, COUNT(*) as count
                   FROM findings f
                   JOIN scans s ON f.scan_id = s.id
                   WHERE s.user_id = ?
                   GROUP BY f.rule_id
                   ORDER BY count DESC""",
                (user_id,),
            )
        else:
            cursor.execute(
                """SELECT rule_id, rule_title, severity, COUNT(*) as count
                   FROM findings
                   GROUP BY rule_id
                   ORDER BY count DESC"""
            )

        dist = [
            {"rule_id": r["rule_id"], "title": r["rule_title"], "severity": r["severity"], "count": r["count"]}
            for r in cursor.fetchall()
        ]
        db.close()
        return {"rules": dist}

    @staticmethod
    def get_severity_breakdown(user_id: int | None = None) -> dict:
        db = get_db_connection(current_app.config["DATABASE_PATH"])
        cursor = db.cursor()

        if user_id:
            cursor.execute(
                """SELECT f.severity, COUNT(*) as count
                   FROM findings f
                   JOIN scans s ON f.scan_id = s.id
                   WHERE s.user_id = ?
                   GROUP BY f.severity""",
                (user_id,),
            )
        else:
            cursor.execute("SELECT severity, COUNT(*) as count FROM findings GROUP BY severity")

        counts: dict = defaultdict(int)
        for r in cursor.fetchall():
            counts[r["severity"]] = r["count"]
        db.close()

        return {
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "info": counts["info"],
        }

    @staticmethod
    def get_most_vulnerable_files(user_id: int | None = None, limit: int = 10) -> list:
        db = get_db_connection(current_app.config["DATABASE_PATH"])
        cursor = db.cursor()

        if user_id:
            cursor.execute(
                """SELECT f.file_name,
                          COUNT(*) as finding_count,
                          SUM(CASE WHEN f.severity='critical' THEN 1 ELSE 0 END) as critical_count,
                          SUM(CASE WHEN f.severity='high' THEN 1 ELSE 0 END) as high_count
                   FROM findings f
                   JOIN scans s ON f.scan_id = s.id
                   WHERE s.user_id = ?
                   GROUP BY f.file_name
                   ORDER BY finding_count DESC
                   LIMIT ?""",
                (user_id, limit),
            )
        else:
            cursor.execute(
                """SELECT file_name,
                          COUNT(*) as finding_count,
                          SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical_count,
                          SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high_count
                   FROM findings
                   GROUP BY file_name
                   ORDER BY finding_count DESC
                   LIMIT ?""",
                (limit,),
            )

        rows = [
            {
                "filename": r["file_name"],
                "total_findings": r["finding_count"],
                "critical": r["critical_count"],
                "high": r["high_count"],
            }
            for r in cursor.fetchall()
        ]
        db.close()
        return rows

    @staticmethod
    def get_improvement_metrics(user_id: int) -> dict:
        """Compare findings in the last 30 days vs the previous 30 days."""
        db = get_db_connection(current_app.config["DATABASE_PATH"])
        cursor = db.cursor()

        cursor.execute(
            """SELECT
                 SUM(CASE WHEN created_at > datetime('now','-30 days') THEN total_findings ELSE 0 END) AS recent,
                 SUM(CASE WHEN created_at BETWEEN datetime('now','-60 days') AND datetime('now','-30 days')
                          THEN total_findings ELSE 0 END) AS older
               FROM scans
               WHERE user_id = ? AND scan_status='completed'""",
            (user_id,),
        )
        row = cursor.fetchone()
        db.close()

        recent = row["recent"] or 0
        older = row["older"] or 0
        pct = round(((older - recent) / older) * 100, 2) if older > 0 else 0.0

        return {
            "recent_findings": recent,
            "previous_findings": older,
            "improvement_percentage": pct,
            "trend": "improving" if pct > 0 else ("same" if pct == 0 else "worsening"),
        }

    @staticmethod
    def build_recommendations(critical: int, high: int, md5: int, plaintext: int) -> list[dict]:
        """Return a prioritised list of actionable recommendations."""
        recs = []
        if plaintext > 0:
            recs.append({
                "priority": "Critical",
                "issue": f"{plaintext} instance(s) of plaintext passwords detected",
                "action": "Immediately implement Argon2id password hashing",
            })
        if md5 > 0:
            recs.append({
                "priority": "High",
                "issue": f"{md5} instance(s) of MD5 hashing detected",
                "action": "Replace MD5 with Argon2id, bcrypt, or scrypt",
            })
        if critical == 0 and high == 0:
            recs.append({
                "priority": "Info",
                "issue": "No critical or high-severity password issues detected",
                "action": "Continue regular audits and keep dependencies up to date",
            })
        return recs


class ComplianceMetrics:
    """Organisation-level security posture and compliance metrics."""

    @staticmethod
    def calculate_security_score(admin_id: int = None) -> dict:
        """Return a 0–100 security score for the whole organisation."""
        db = get_db_connection(current_app.config["DATABASE_PATH"])
        cursor = db.cursor()

        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
        )
        counts: dict = defaultdict(int)
        for r in cursor.fetchall():
            counts[r["severity"]] = r["count"]
        db.close()

        weight = (
            counts["critical"] * 50
            + counts["high"] * 30
            + counts["medium"] * 15
            + counts["low"] * 5
        )
        score = round(max(0.0, 100.0 - weight / 10), 2)

        return {
            "security_score": score,
            "grade": ComplianceMetrics._letter_grade(score),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "status": "Critical" if score < 50 else ("Warning" if score < 70 else "Good"),
        }

    @staticmethod
    def _letter_grade(score: float) -> str:
        if score >= 90: return "A+"
        if score >= 80: return "A"
        if score >= 70: return "B"
        if score >= 60: return "C"
        if score >= 50: return "D"
        return "F"

    @staticmethod
    def get_compliance_report(admin_id: int = None) -> dict:
        """Return an OWASP-aligned compliance summary."""
        db = get_db_connection(current_app.config["DATABASE_PATH"])
        cursor = db.cursor()

        cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_active=1")
        active_users = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM scans")
        total_scans = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM findings WHERE rule_id='PWD002'")
        md5_count = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM findings WHERE rule_id='PWD001'")
        plaintext_count = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM findings WHERE rule_id IN ('PWD007')")
        modern_hash_count = cursor.fetchone()["c"]

        db.close()

        items = {
            "no_plaintext_passwords": plaintext_count == 0,
            "no_md5_hashing": md5_count == 0,
            "modern_hashing_in_use": modern_hash_count > 0,
            "regular_security_audits": total_scans >= 1,
            "active_user_base": active_users > 0,
        }

        pct = round((sum(items.values()) / len(items)) * 100, 1)

        # Use the local helper — no cross-class call
        recs = VulnerabilityAnalytics.build_recommendations(
            0, 0, md5_count, plaintext_count
        )

        return {
            "compliance_percentage": pct,
            "items": items,
            "recommendations": recs,
            "total_scans": total_scans,
            "active_users": active_users,
        }
