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
    last_checked  TEXT    NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the ssl_results table if it does not exist."""
    with _connect() as conn:
        conn.execute(_CREATE_TABLE)
        conn.commit()


def upsert_result(result: Dict[str, object]) -> None:
    """Insert or update a scan result for a domain."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO ssl_results (domain, expiry_date, days_left, status, error, last_checked)
            VALUES (:domain, :expiry_date, :days_left, :status, :error, :last_checked)
            ON CONFLICT(domain) DO UPDATE SET
                expiry_date  = excluded.expiry_date,
                days_left    = excluded.days_left,
                status       = excluded.status,
                error        = excluded.error,
                last_checked = excluded.last_checked
            """,
            {
                "domain": result["domain"],
                "expiry_date": result.get("expiry_date"),
                "days_left": result.get("days_left"),
                "status": result.get("status", "ERROR"),
                "error": result.get("error"),
                "last_checked": now,
            },
        )
        conn.commit()


def upsert_results(results: List[Dict[str, object]]) -> None:
    """Batch upsert multiple scan results."""
    for r in results:
        upsert_result(r)


def get_all_results() -> List[Dict[str, object]]:
    """Return all stored results ordered by days_left ascending (most urgent first)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT domain, expiry_date, days_left, status, error, last_checked "
            "FROM ssl_results ORDER BY days_left ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_result_by_domain(domain: str) -> Optional[Dict[str, object]]:
    """Return a single result by domain name, or None."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT domain, expiry_date, days_left, status, error, last_checked "
            "FROM ssl_results WHERE domain = ?",
            (domain.strip().lower(),),
        ).fetchone()
    return dict(row) if row else None


# Auto-initialise when this module is first imported.
init_db()
