"""Phase 2.5 ownership storage and migration coverage."""

from __future__ import annotations

import hashlib
import importlib.util
import sqlite3
from pathlib import Path

import pytest

from src.agent.agent_store import AgentStore
from src.web.analysis_manager import AnalysisManager


MIGRATION_PATH = (
    Path(__file__).parents[1]
    / "src"
    / "db"
    / "migrations"
    / "003_add_session_ownership.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "session_ownership_migration",
        MIGRATION_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _create_legacy_db(path: Path, table: str) -> None:
    connection = sqlite3.connect(str(path))
    if table == "agent_sessions":
        connection.execute(
            """
            CREATE TABLE agent_sessions (
                id TEXT PRIMARY KEY,
                case_id TEXT,
                goal TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                playbook_id TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                summary TEXT,
                findings TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}'
            )
            """
        )
        connection.execute(
            "INSERT INTO agent_sessions (id, goal, created_at) VALUES (?, ?, ?)",
            ("legacy-session", "legacy", "2026-01-01T00:00:00+00:00"),
        )
    else:
        connection.execute(
            """
            CREATE TABLE analysis_jobs (
                id TEXT PRIMARY KEY,
                analysis_type TEXT NOT NULL,
                params TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'queued',
                progress INTEGER NOT NULL DEFAULT 0,
                current_step TEXT DEFAULT '',
                verdict TEXT,
                score INTEGER,
                result TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO analysis_jobs (id, analysis_type, created_at) VALUES (?, ?, ?)",
            ("legacy-job", "ioc", "2026-01-01T00:00:00+00:00"),
        )
    connection.commit()
    connection.close()


def _columns(path: Path, table: str) -> list[str]:
    connection = sqlite3.connect(str(path))
    result = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
    connection.close()
    return result


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_migration_adds_nullable_user_id_and_is_idempotent(tmp_path):
    agent_db = tmp_path / "agent.db"
    analysis_db = tmp_path / "analysis_jobs.db"
    _create_legacy_db(agent_db, "agent_sessions")
    _create_legacy_db(analysis_db, "analysis_jobs")

    migration = _load_migration()
    migration.migrate(agent_db, analysis_db)

    assert "user_id" in _columns(agent_db, "agent_sessions")
    assert "user_id" in _columns(analysis_db, "analysis_jobs")
    assert (tmp_path / "agent.db.pre-003-session-ownership.bak").exists()
    assert (tmp_path / "analysis_jobs.db.pre-003-session-ownership.bak").exists()

    connection = sqlite3.connect(str(agent_db))
    assert connection.execute(
        "SELECT user_id FROM agent_sessions WHERE id = 'legacy-session'"
    ).fetchone() == (None,)
    connection.close()

    migration.migrate(agent_db, analysis_db)
    assert "user_id" in _columns(agent_db, "agent_sessions")
    assert "user_id" in _columns(analysis_db, "analysis_jobs")


def test_migration_restores_first_database_when_second_database_fails(tmp_path, monkeypatch):
    agent_db = tmp_path / "agent.db"
    analysis_db = tmp_path / "analysis_jobs.db"
    _create_legacy_db(agent_db, "agent_sessions")
    _create_legacy_db(analysis_db, "analysis_jobs")
    before_agent = _digest(agent_db)
    before_analysis = _digest(analysis_db)

    migration = _load_migration()
    original_upgrade = migration.upgrade

    def fail_after_second_upgrade(connection, table_name, index_name):
        original_upgrade(connection, table_name, index_name)
        if table_name == "analysis_jobs":
            raise RuntimeError("forced migration failure")

    monkeypatch.setattr(migration, "upgrade", fail_after_second_upgrade)

    with pytest.raises(RuntimeError, match="forced migration failure"):
        migration.migrate(agent_db, analysis_db)

    assert _digest(agent_db) == before_agent
    assert _digest(analysis_db) == before_analysis


def test_agent_store_filters_sessions_by_user_and_keeps_admin_unscoped(tmp_path):
    store = AgentStore(db_path=str(tmp_path / "agent.db"))
    own = store.create_session("own", user_id=101)
    other = store.create_session("other", user_id=202)
    legacy = store.create_session("legacy")

    assert store.get_session(own, user_id=101)["id"] == own
    assert store.get_session(other, user_id=101) is None
    assert store.get_session(legacy, user_id=101) is None

    assert {row["id"] for row in store.list_sessions(user_id=101)} == {own}
    assert {row["id"] for row in store.list_sessions(user_id=None)} == {
        own,
        other,
        legacy,
    }


def test_analysis_manager_filters_jobs_by_user_and_keeps_admin_unscoped(tmp_path):
    manager = AnalysisManager(db_path=str(tmp_path / "analysis_jobs.db"))
    own = manager.create_job("ioc", {"value": "own"}, user_id=101)
    other = manager.create_job("ioc", {"value": "other"}, user_id=202)
    legacy = manager.create_job("ioc", {"value": "legacy"})

    assert manager.get_job(own, user_id=101)["id"] == own
    assert manager.get_job(other, user_id=101) is None
    assert manager.get_job(legacy, user_id=101) is None

    assert {row["id"] for row in manager.list_jobs(user_id=101)} == {own}
    assert {row["id"] for row in manager.list_jobs(user_id=None)} == {
        own,
        other,
        legacy,
    }
