"""Migration for the Phase 1 authentication tables."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


ROLES = (
    "SOC Analyst Tier 1-2",
    "Incident Responder",
    "Threat Hunter",
)


def upgrade(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (
                role IN (
                    'SOC Analyst Tier 1-2',
                    'Incident Responder',
                    'Threat Hunter'
                )
            ),
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            jti TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    connection.commit()


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
