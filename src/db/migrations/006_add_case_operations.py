"""Add idempotent Team Lead case-operation fields."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from src.web.case_store import ensure_cases_schema


def upgrade(connection: sqlite3.Connection) -> None:
    """Add assignee/priority while preserving all existing case rows."""
    ensure_cases_schema(connection)
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
        else os.getenv(
            "CASES_DB_PATH",
            str(Path.home() / ".blue-team-assistant" / "cache" / "cases.db"),
        )
    )
