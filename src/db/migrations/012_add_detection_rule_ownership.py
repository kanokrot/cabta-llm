"""Add per-rule ownership tracking to the analysis-jobs database."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


DEFAULT_ANALYSIS_DB = (
    Path.home() / ".blue-team-assistant" / "cache" / "analysis_jobs.db"
)


def upgrade(connection: sqlite3.Connection) -> None:
    """Create the idempotent latest-editor table for detection rules."""
    try:
        connection.execute("BEGIN")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_rule_ownership (
                analysis_id TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                last_edited_by INTEGER NOT NULL,
                last_edited_at TEXT NOT NULL,
                PRIMARY KEY (analysis_id, rule_type),
                FOREIGN KEY (analysis_id) REFERENCES analysis_jobs(id)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_detection_rule_ownership_editor
            ON detection_rule_ownership(last_edited_by)
            """
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def migrate(db_path: str | os.PathLike[str] | None = None) -> None:
    path = Path(db_path or os.getenv("ANALYSIS_DB_PATH", str(DEFAULT_ANALYSIS_DB)))
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as connection:
        upgrade(connection)


if __name__ == "__main__":
    migrate(sys.argv[1] if len(sys.argv) > 1 else None)
