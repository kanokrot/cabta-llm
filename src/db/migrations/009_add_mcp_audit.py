"""Add MCP management audit records without storing sensitive configuration."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


def upgrade(connection: sqlite3.Connection) -> None:
    """Create the MCP management audit table atomically and idempotently."""
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute("BEGIN")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_management_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL CHECK (
                    action IN (
                        'connect', 'disconnect', 'add_server',
                        'delete_server', 'check'
                    )
                ),
                server_name TEXT NOT NULL,
                status TEXT NOT NULL,
                occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS mcp_management_audit_actor_idx "
            "ON mcp_management_audit(actor_user_id, occurred_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS mcp_management_audit_server_idx "
            "ON mcp_management_audit(server_name, occurred_at)"
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
