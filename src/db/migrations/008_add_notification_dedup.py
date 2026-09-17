"""Add transactional notification deduplication and digest queues (Phase 5)."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


def upgrade(connection: sqlite3.Connection) -> None:
    """Create Phase 5 notification tables; safe to run repeatedly."""
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_dedup (
                dedup_key TEXT NOT NULL UNIQUE,
                recipient_user_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_summary TEXT NOT NULL CHECK (json_valid(payload_summary)),
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                sent_at TEXT,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_digest_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_user_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_summary TEXT NOT NULL CHECK (json_valid(payload_summary)),
                queued_at TEXT NOT NULL,
                sent_at TEXT,
                FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS notification_dedup_recipient_idx "
            "ON notification_dedup(recipient_user_id, expires_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS notification_digest_pending_idx "
            "ON notification_digest_queue(recipient_user_id, sent_at, queued_at)"
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
