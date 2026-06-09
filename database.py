"""
Database module — SQLite persistence for SSL scan results.
"""

import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

from config import DB_FILE

# ── Schema ──────────────────────────────────────────────────────────────
_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS ssl_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain        TEXT    NOT NULL UNIQUE,
    expiry_date   TEXT,
    days_left     INTEGER,
    status        TEXT,
    error         TEXT,
    last_checked  TEXT    NOT NULL,
    issuer        TEXT,
    subject       TEXT,
    serial_number TEXT,
    is_valid      INTEGER DEFAULT 0
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they do not exist and perform column migrations."""
    with _connect() as conn:
        conn.execute(_CREATE_TABLE)
        
        # Column migration check
        cursor = conn.execute("PRAGMA table_info(ssl_results)")
        columns = [row["name"] for row in cursor.fetchall()]
        if "issuer" not in columns:
            conn.execute("ALTER TABLE ssl_results ADD COLUMN issuer TEXT")
        if "subject" not in columns:
            conn.execute("ALTER TABLE ssl_results ADD COLUMN subject TEXT")
        if "serial_number" not in columns:
            conn.execute("ALTER TABLE ssl_results ADD COLUMN serial_number TEXT")
        if "is_valid" not in columns:
            conn.execute("ALTER TABLE ssl_results ADD COLUMN is_valid INTEGER DEFAULT 0")

        # Create history table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            domain        TEXT    NOT NULL,
            timestamp     TEXT    NOT NULL,
            days_left     INTEGER,
            status        TEXT,
            error         TEXT
        );
        """)
        conn.commit()


def upsert_result(result: Dict[str, object]) -> None:
    """Insert or update a scan result for a domain and record to history."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO ssl_results (domain, expiry_date, days_left, status, error, last_checked, issuer, subject, serial_number, is_valid)
            VALUES (:domain, :expiry_date, :days_left, :status, :error, :last_checked, :issuer, :subject, :serial_number, :is_valid)
            ON CONFLICT(domain) DO UPDATE SET
                expiry_date   = excluded.expiry_date,
                days_left     = excluded.days_left,
                status        = excluded.status,
                error         = excluded.error,
                last_checked  = excluded.last_checked,
                issuer        = excluded.issuer,
                subject       = excluded.subject,
                serial_number = excluded.serial_number,
                is_valid      = excluded.is_valid
            """,
            {
                "domain": result["domain"],
                "expiry_date": result.get("expiry_date"),
                "days_left": result.get("days_left"),
                "status": result.get("status", "ERROR"),
                "error": result.get("error"),
                "last_checked": now,
                "issuer": result.get("issuer"),
                "subject": result.get("subject"),
                "serial_number": result.get("serial_number"),
                "is_valid": 1 if result.get("is_valid") else 0,
            },
        )
        
        # Log event in history table
        conn.execute(
            """
            INSERT INTO scan_history (domain, timestamp, days_left, status, error)
            VALUES (:domain, :timestamp, :days_left, :status, :error)
            """,
            {
                "domain": result["domain"],
                "timestamp": now,
                "days_left": result.get("days_left"),
                "status": result.get("status", "ERROR"),
                "error": result.get("error"),
            }
        )
        conn.commit()


def upsert_results(results: List[Dict[str, object]]) -> None:
    """Batch upsert multiple scan results."""
    for r in results:
        upsert_result(r)


def get_all_results() -> List[Dict[str, object]]:
    """Return all stored results ordered by urgency (NULL errors at the end, lowest days_left first)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT domain, expiry_date, days_left, status, error, last_checked, issuer, subject, serial_number, is_valid "
            "FROM ssl_results ORDER BY CASE WHEN days_left IS NULL THEN 1 ELSE 0 END, days_left ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_result_by_domain(domain: str) -> Optional[Dict[str, object]]:
    """Return a single result by domain name, or None."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT domain, expiry_date, days_left, status, error, last_checked, issuer, subject, serial_number, is_valid "
            "FROM ssl_results WHERE domain = ?",
            (domain.strip().lower(),),
        ).fetchone()
    return dict(row) if row else None


def delete_domain(domain: str) -> None:
    """Remove a domain from the database."""
    with _connect() as conn:
        conn.execute("DELETE FROM ssl_results WHERE domain = ?", (domain.strip().lower(),))
        conn.execute("DELETE FROM scan_history WHERE domain = ?", (domain.strip().lower(),))
        conn.commit()


def get_all_monitored_domains() -> List[str]:
    """Return list of all domain names currently tracked."""
    with _connect() as conn:
        rows = conn.execute("SELECT domain FROM ssl_results").fetchall()
    return [row["domain"] for row in rows]


def get_domain_history(domain: str) -> List[Dict[str, object]]:
    """Return scan history for a specific domain ordered by timestamp descending."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT timestamp, days_left, status, error FROM scan_history "
            "WHERE domain = ? ORDER BY timestamp DESC",
            (domain.strip().lower(),),
        ).fetchall()
    return [dict(row) for row in rows]


# Auto-initialise when this module is first imported.
init_db()
