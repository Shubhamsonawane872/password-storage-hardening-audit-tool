"""Database initialisation, schema, and connection helpers."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path


def get_db_connection(database_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(app) -> None:
    """Create the schema if it does not already exist, then run migrations."""
    db_path: str = app.config["DATABASE_PATH"]
    os.makedirs(Path(db_path).parent if Path(db_path).parent.name else Path("."), exist_ok=True)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    fresh = cursor.fetchone() is None

    if fresh:
        _create_schema(cursor)
        conn.commit()
    else:
        _run_migrations(cursor, conn)

    cursor.close()
    conn.close()


def _create_schema(cursor: sqlite3.Cursor) -> None:
    """Full schema — used when starting with an empty database."""

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            email         TEXT    UNIQUE NOT NULL,
            email_lower   TEXT    UNIQUE,          -- normalised lookup column
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'user',
            is_active     INTEGER NOT NULL DEFAULT 1,
            theme         TEXT    NOT NULL DEFAULT 'light',
            notify_email  INTEGER NOT NULL DEFAULT 1,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id             INTEGER NOT NULL,
            original_filename   TEXT,
            scan_status         TEXT    NOT NULL DEFAULT 'pending',
            total_files_scanned INTEGER DEFAULT 0,
            total_findings      INTEGER DEFAULT 0,
            critical_count      INTEGER DEFAULT 0,   -- NEW separate critical column
            high_count          INTEGER DEFAULT 0,
            medium_count        INTEGER DEFAULT 0,
            low_count           INTEGER DEFAULT 0,
            info_count          INTEGER DEFAULT 0,
            security_score      REAL    DEFAULT NULL,
            security_grade      TEXT    DEFAULT NULL,
            created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at        TIMESTAMP,
            error_message       TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL,
            rule_id        TEXT    NOT NULL,
            rule_title     TEXT    NOT NULL,
            severity       TEXT    NOT NULL,
            file_name      TEXT,
            line_number    INTEGER,
            evidence       TEXT,
            description    TEXT,
            recommendation TEXT,
            confidence     REAL    DEFAULT 0.8,
            created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER,
            action        TEXT    NOT NULL,
            resource_type TEXT,
            resource_id   INTEGER,
            ip_address    TEXT,
            user_agent    TEXT,
            status        TEXT    DEFAULT 'success',
            details       TEXT,
            timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            token_hash   TEXT    UNIQUE NOT NULL,
            name         TEXT,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at   TIMESTAMP NOT NULL,
            last_used_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    _create_indexes(cursor)


def _create_indexes(cursor: sqlite3.Cursor) -> None:
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id        ON scans(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status         ON scans(scan_status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id     ON findings(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity    ON findings(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_rule        ON findings(rule_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user           ON audit_logs(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts             ON audit_logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user          ON api_tokens(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash          ON api_tokens(token_hash)")


def _run_migrations(cursor: sqlite3.Cursor, conn: sqlite3.Connection) -> None:
    """Non-destructive ALTER TABLE migrations for existing databases."""
    _add_column_if_missing(cursor, "scans",    "critical_count",  "INTEGER DEFAULT 0")
    _add_column_if_missing(cursor, "scans",    "security_score",  "REAL    DEFAULT NULL")
    _add_column_if_missing(cursor, "scans",    "security_grade",  "TEXT    DEFAULT NULL")
    _add_column_if_missing(cursor, "findings", "confidence",      "REAL    DEFAULT 0.8")
    _add_column_if_missing(cursor, "users",    "theme",           "TEXT    NOT NULL DEFAULT 'light'")
    _add_column_if_missing(cursor, "users",    "notify_email",    "INTEGER NOT NULL DEFAULT 1")
    _add_column_if_missing(cursor, "users",    "email_lower",     "TEXT")
    _create_indexes(cursor)
    conn.commit()


def _add_column_if_missing(cursor, table: str, column: str, definition: str) -> None:
    cursor.execute(f"PRAGMA table_info({table})")
    cols = [r["name"] for r in cursor.fetchall()]
    if column not in cols:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


# ── Request-scoped helpers (used via Flask g) ─────────────────────────────────

def get_query_db():
    from flask import g, current_app
    if "db" not in g:
        g.db = get_db_connection(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(e=None):
    from flask import g
    db = g.pop("db", None)
    if db is not None:
        db.close()
