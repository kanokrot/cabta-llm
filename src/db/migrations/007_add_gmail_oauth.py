"""Add per-user Gmail OAuth credential and state storage (Phase 4)."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


def upgrade(connection: sqlite3.Connection) -> None:
    """Create Gmail OAuth tables atomically and safely on repeat runs."""
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("BEGIN")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS user_gmail_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                google_subject TEXT NOT NULL,
                google_email TEXT NOT NULL,
                refresh_token_ciphertext TEXT NOT NULL,
                token_key_version INTEGER NOT NULL,
                granted_scopes TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_refresh_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gmail_oauth_states (
                state_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                redirect_uri TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gmail_oauth_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event TEXT NOT NULL CHECK (event IN ('connect', 'disconnect', 'refresh_failed')),
                google_subject TEXT,
                google_email TEXT,
                occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS gmail_oauth_states_user_idx "
            "ON gmail_oauth_states(user_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS gmail_oauth_audit_user_idx "
            "ON gmail_oauth_audit(user_id)"
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
