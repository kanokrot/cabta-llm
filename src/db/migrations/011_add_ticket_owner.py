"""Add nullable owner IDs to the separate SQLite ticket database."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from src.integrations.ticketing import ensure_owner_schema


def upgrade(connection: sqlite3.Connection) -> None:
    """Add ticket ownership storage without assigning legacy rows an owner."""
    try:
        connection.execute("BEGIN")
        ensure_owner_schema(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def migrate(db_path: str | os.PathLike[str] | None = None) -> None:
    path = Path(db_path or os.getenv("TICKETING_DB_PATH", "data/tickets/tickets.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as connection:
        upgrade(connection)


if __name__ == "__main__":
    migrate(sys.argv[1] if len(sys.argv) > 1 else None)
