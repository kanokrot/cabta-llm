"""Migration for Phase 1.5 usernames, admin role, and invite tokens."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


def upgrade(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("BEGIN")
    try:
        connection.executescript(
            """
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                username TEXT UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (
                    role IN (
                        'SOC Analyst Tier 1-2',
                        'Incident Responder',
                        'Threat Hunter',
                        'admin'
                    )
                ),
                is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            INSERT INTO users_new
                (id, email, username, password_hash, role, is_active, created_at)
            SELECT
                id, email, 'user_' || id, password_hash, role, is_active, created_at
            FROM users;

            CREATE TABLE auth_sessions_new (
                jti TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users_new(id) ON DELETE CASCADE
            );

            INSERT INTO auth_sessions_new
                (jti, user_id, expires_at, revoked_at, created_at)
            SELECT jti, user_id, expires_at, revoked_at, created_at
            FROM auth_sessions;

            DROP TABLE auth_sessions;
            DROP TABLE users;
            ALTER TABLE users_new RENAME TO users;
            ALTER TABLE auth_sessions_new RENAME TO auth_sessions;

            CREATE TABLE invite_tokens (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL COLLATE NOCASE,
                role TEXT NOT NULL CHECK (
                    role IN (
                        'SOC Analyst Tier 1-2',
                        'Incident Responder',
                        'Threat Hunter',
                        'admin'
                    )
                ),
                invited_by INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE RESTRICT
            );

            CREATE INDEX invite_tokens_email_idx ON invite_tokens(email);
            """
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


def migrate(db_path: str) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as connection:
        upgrade(connection)


if __name__ == "__main__":
    migrate(
        sys.argv[1]
        if len(sys.argv) > 1
        else os.getenv("AUTH_DB_PATH", "src/db/auth.db")
    )
