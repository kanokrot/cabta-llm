"""Make the agent audit log capable of recording cross-user reads."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from src.agent.agent_store import ensure_audit_schema


def upgrade(connection: sqlite3.Connection) -> None:
    """Upgrade the existing audit table while preserving all old entries."""
    ensure_audit_schema(connection)
    connection.commit()


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
        else os.getenv("AGENT_DB_PATH", str(Path.home() / ".blue-team-assistant" / "cache" / "agent.db"))
    )
