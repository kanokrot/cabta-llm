"""Add nullable user ownership to agent sessions and analysis jobs."""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
from pathlib import Path


DEFAULT_AGENT_DB = Path.home() / ".blue-team-assistant" / "cache" / "agent.db"
DEFAULT_ANALYSIS_DB = (
    Path.home() / ".blue-team-assistant" / "cache" / "analysis_jobs.db"
)

TABLES = (
    ("agent_sessions", "idx_sessions_user_id"),
    ("analysis_jobs", "idx_jobs_user_id"),
)


def _backup_path(db_path: Path) -> Path:
    return db_path.with_name(f"{db_path.name}.pre-003-session-ownership.bak")


def _backup(db_path: Path) -> Path:
    backup = _backup_path(db_path)
    shutil.copy2(db_path, backup)
    return backup


def upgrade(
    connection: sqlite3.Connection,
    table_name: str,
    index_name: str,
) -> None:
    columns = {
        row[1]
        for row in connection.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()
    }

    if "user_id" not in columns:
        connection.execute(
            f"ALTER TABLE {table_name} ADD COLUMN user_id INTEGER"
        )

    connection.execute(
        f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name}(user_id)"
    )


def _migrate_one(
    db_path: Path,
    table_name: str,
    index_name: str,
) -> Path:
    backup = _backup(db_path)
    connection = sqlite3.connect(str(db_path))
    try:
        connection.execute("BEGIN")
        upgrade(connection, table_name, index_name)
        connection.commit()
        return backup
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def migrate(
    agent_db_path: str | os.PathLike[str] = DEFAULT_AGENT_DB,
    analysis_db_path: str | os.PathLike[str] = DEFAULT_ANALYSIS_DB,
) -> None:
    paths = [
        (Path(agent_db_path), *TABLES[0]),
        (Path(analysis_db_path), *TABLES[1]),
    ]
    completed: list[tuple[Path, Path]] = []

    try:
        for db_path, table_name, index_name in paths:
            backup = _migrate_one(db_path, table_name, index_name)
            completed.append((db_path, backup))
    except Exception:
        for db_path, backup in completed:
            shutil.copy2(backup, db_path)
        raise


if __name__ == "__main__":
    migrate(
        sys.argv[1] if len(sys.argv) > 1 else DEFAULT_AGENT_DB,
        sys.argv[2] if len(sys.argv) > 2 else DEFAULT_ANALYSIS_DB,
    )
