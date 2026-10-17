"""Background job scheduling for automated scans."""
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler()

# Stored at startup so the scheduler thread can reach the real DB path.
_app_config: dict = {}


def start_scheduler(app=None):
    """Start the background scheduler. Must be called after create_app."""
    global _app_config
    if app:
        _app_config = {
            'DATABASE_PATH': app.config.get('DATABASE_PATH', 'instance/password_audit.db'),
        }
        try:
            scheduler.configure(timezone=app.config.get('TIMEZONE', 'UTC'))
        except Exception:
            pass  # already configured

    if not scheduler.running:
        scheduler.start()
        logger.info("Background scheduler started")


def stop_scheduler():
    """Gracefully stop the background scheduler."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Background scheduler stopped")


def schedule_scan(scan_id: int, user_id: int, schedule_time: str):
    """
    Add a recurring scan job via cron expression.

    Returns the job_id string on success, or None on failure.
    """
    try:
        job_id = f"scan_{scan_id}_{user_id}_{int(datetime.now().timestamp())}"
        scheduler.add_job(
            func=execute_scheduled_scan,
            trigger=CronTrigger.from_crontab(schedule_time),
            args=[scan_id, user_id],
            id=job_id,
            name=f"Scheduled Scan {scan_id}",
            replace_existing=True,
        )
        logger.info("Scheduled scan %s for user %s (cron: %s)", scan_id, user_id, schedule_time)
        return job_id
    except Exception as exc:
        logger.error("Failed to schedule scan %s: %s", scan_id, exc)
        return None


def execute_scheduled_scan(scan_id: int, user_id: int):
    """
    Execute a recurring scan job.

    This runs in the APScheduler thread pool, outside of a Flask request
    context, so we open the DB directly using the stored config path.
    """
    from app.db import get_db_connection  # local import to avoid circular dep

    db_path = _app_config.get('DATABASE_PATH', 'instance/password_audit.db')

    try:
        db = get_db_connection(db_path)
        cursor = db.cursor()

        # Fetch the original scan so we know which file to re-scan
        cursor.execute(
            "SELECT original_filename FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, user_id),
        )
        original = cursor.fetchone()
        if not original:
            logger.warning("Scheduled scan %s: original scan not found", scan_id)
            db.close()
            return

        # Create a new scan record for this execution
        cursor.execute(
            """INSERT INTO scans (user_id, original_filename, scan_status)
               VALUES (?, ?, 'pending')""",
            (user_id, f"[scheduled] {original['original_filename']}"),
        )
        new_scan_id = cursor.lastrowid

        cursor.execute(
            """INSERT INTO audit_logs (user_id, action, resource_type, resource_id, status)
               VALUES (?, 'scheduled_scan_triggered', 'scan', ?, 'success')""",
            (user_id, new_scan_id),
        )
        db.commit()
        db.close()
        logger.info("Scheduled scan triggered → new scan id=%s", new_scan_id)

    except Exception as exc:
        logger.error("Failed to execute scheduled scan %s: %s", scan_id, exc)


def list_scheduled_jobs(user_id: int = None):
    """Return a list of scheduled job metadata, optionally filtered by user."""
    jobs = []
    for job in scheduler.get_jobs():
        if user_id and f"_{user_id}_" not in job.id:
            continue
        jobs.append(
            {
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
            }
        )
    return jobs


def cancel_scheduled_job(job_id: str) -> bool:
    """Remove a scheduled job by its ID. Returns True on success."""
    try:
        scheduler.remove_job(job_id)
        logger.info("Cancelled scheduled job %s", job_id)
        return True
    except Exception as exc:
        logger.error("Failed to cancel job %s: %s", job_id, exc)
        return False
