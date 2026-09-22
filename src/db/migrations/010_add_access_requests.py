"""Create the public access-request queue for admin review."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


def upgrade(connection: sqlite3.Connection) -> None:
    """Create the access request table and its lookup indexes idempotently."""
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("BEGIN")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE,
                requested_role TEXT NOT NULL CHECK (
                    requested_role IN (
                        'SOC Analyst Tier 1-2',
                        'Incident Responder',
                        'Threat Hunter',
                        'Team Lead',
                        'admin'
                    )
                ),
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (
                    status IN ('pending', 'approved', 'rejected')
                ),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                decided_at TEXT,
                decided_by INTEGER,
                FOREIGN KEY (decided_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS access_requests_status_idx "
            "ON access_requests(status, created_at)"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS access_requests_pending_email_idx "
            "ON access_requests(email) WHERE status = 'pending'"
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def migrate(db_path: str | os.PathLike[str] | None = None) -> None:
    path = Path(db_path or os.getenv("AUTH_DB_PATH", "src/db/auth.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as connection:
        upgrade(connection)


if __name__ == "__main__":
    migrate(sys.argv[1] if len(sys.argv) > 1 else None)
