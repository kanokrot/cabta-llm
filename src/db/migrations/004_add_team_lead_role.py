"""Add the Team Lead role without changing earlier migrations."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


TEAM_LEAD = "Team Lead"


def _table_sql(connection: sqlite3.Connection, table_name: str) -> str:
    row = connection.execute(
        """
        SELECT sql
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        """,
        (table_name,),
    ).fetchone()
    if row is None or not row[0]:
        raise RuntimeError(f"Required table does not exist: {table_name}")
    return row[0]


def _contains_team_lead(
    connection: sqlite3.Connection,
    table_name: str,
) -> bool:
    return TEAM_LEAD in _table_sql(connection, table_name)


def upgrade(connection: sqlite3.Connection) -> None:
    """Rebuild users and invite_tokens atomically with the expanded CHECK."""
    connection.execute("PRAGMA foreign_keys = OFF")

    try:
        baseline_violations = {
            tuple(row)
            for row in connection.execute("PRAGMA foreign_key_check").fetchall()
        }
        connection.execute("BEGIN IMMEDIATE")

        users_done = _contains_team_lead(connection, "users")
        invites_done = _contains_team_lead(connection, "invite_tokens")

        if users_done and invites_done:
            connection.commit()
            return

        if users_done != invites_done:
            raise RuntimeError(
                "Partial Team Lead migration detected; refusing to continue"
            )

        connection.execute(
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
                        'Team Lead',
                        'admin'
                    )
                ),
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT INTO users_new
                (id, email, username, password_hash, role, is_active, created_at)
            SELECT
                id, email, username, password_hash, role, is_active, created_at
            FROM users
            """
        )

        connection.execute(
            """
            CREATE TABLE invite_tokens_new (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL COLLATE NOCASE,
                role TEXT NOT NULL CHECK (
                    role IN (
                        'SOC Analyst Tier 1-2',
                        'Incident Responder',
                        'Threat Hunter',
                        'Team Lead',
                        'admin'
                    )
                ),
                invited_by INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (invited_by) REFERENCES users(id)
                    ON DELETE RESTRICT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO invite_tokens_new
                (token, email, role, invited_by, expires_at, used_at, created_at)
            SELECT
                token, email, role, invited_by, expires_at, used_at, created_at
            FROM invite_tokens
            """
        )

        connection.execute("DROP TABLE invite_tokens")
        connection.execute("DROP TABLE users")
        connection.execute("ALTER TABLE users_new RENAME TO users")
        connection.execute(
            "ALTER TABLE invite_tokens_new RENAME TO invite_tokens"
        )
        connection.execute(
            "CREATE INDEX invite_tokens_email_idx ON invite_tokens(email)"
        )

        after_violations = {
            tuple(row)
            for row in connection.execute("PRAGMA foreign_key_check").fetchall()
        }
        new_violations = after_violations - baseline_violations
        if new_violations:
            raise RuntimeError(
                f"Foreign-key violations introduced by migration: {new_violations!r}"
            )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


def migrate(db_path: str) -> None:
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"Database does not exist: {path}")

    with sqlite3.connect(str(path)) as connection:
        upgrade(connection)


if __name__ == "__main__":
    migrate(
        sys.argv[1]
        if len(sys.argv) > 1
        else os.getenv("AUTH_DB_PATH", "src/db/auth.db")
    )
