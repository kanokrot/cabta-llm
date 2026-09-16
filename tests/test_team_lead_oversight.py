"""Phase 2 Team Lead read-only oversight and audit coverage."""

from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.agent.agent_store import AgentStore
from src.web.analysis_manager import AnalysisManager
from src.web.auth import TEAM_LEAD, get_current_user
from src.web.routes import analysis as analysis_routes
from src.web.routes import dashboard as dashboard_routes


ROOT = Path(__file__).parents[1]


def _load_migration(filename: str):
    path = ROOT / "src" / "db" / "migrations" / filename
    spec = importlib.util.spec_from_file_location(filename.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _team_lead() -> dict:
    return {
        "id": 900,
        "email": "lead@example.test",
        "username": "team-lead",
        "role": TEAM_LEAD,
        "is_active": 1,
    }


def test_team_lead_reads_trimmed_analysis_and_dashboard_and_audits_each_read(
    tmp_path, monkeypatch
) -> None:
    analysis_manager = AnalysisManager(str(tmp_path / "analysis.db"))
    agent_store = AgentStore(str(tmp_path / "agent.db"))
    job_id = analysis_manager.create_job(
        "file",
        {
            "filename": "sample.exe",
            "sha256": "hash-1",
            "size": 42,
            "temp_path": "C:/private/raw/sample.exe",
            "raw_source": "must-not-be-returned",
        },
        user_id=101,
    )
    analysis_manager.complete_job(
        job_id,
        {
            "summary": "safe summary",
            "confidence": 0.9,
            "raw_source": "must-not-be-returned",
            "provider_payload": {"secret": "must-not-be-returned"},
        },
        verdict="SUSPICIOUS",
        score=75,
    )

    monkeypatch.setattr(
        analysis_routes, "get_user_ids_by_role", lambda _role: [101]
    )
    monkeypatch.setattr(
        dashboard_routes, "get_user_ids_by_role", lambda _role: [101]
    )

    app = FastAPI()
    app.state.analysis_manager = analysis_manager
    app.state.agent_store = agent_store
    app.dependency_overrides[get_current_user] = _team_lead
    app.include_router(analysis_routes.router, prefix="/api/analysis")
    app.include_router(dashboard_routes.router, prefix="/api/dashboard")

    with TestClient(app) as client:
        analysis_response = client.get(f"/api/analysis/{job_id}")
        dashboard_response = client.get("/api/dashboard/recent")

    assert analysis_response.status_code == 200
    analysis_payload = analysis_response.json()
    assert analysis_payload["filename"] == "sample.exe"
    assert analysis_payload["summary"] == "safe summary"
    assert "params" not in analysis_payload
    assert "result" not in analysis_payload
    assert "temp_path" not in analysis_payload
    assert "raw_source" not in analysis_payload

    assert dashboard_response.status_code == 200
    dashboard_payload = dashboard_response.json()
    assert dashboard_payload["items"] == dashboard_payload["analyses"]
    assert dashboard_payload["items"][0]["filename"] == "sample.exe"
    assert "result" not in dashboard_payload["items"][0]
    assert "temp_path" not in dashboard_payload["items"][0]

    cross_reads = [
        entry
        for entry in agent_store.get_audit_log()
        if entry["action"] == "cross_user_read"
    ]
    assert len(cross_reads) == 2
    assert {entry["resource_type"] for entry in cross_reads} == {
        "analysis",
        "dashboard",
    }
    for entry in cross_reads:
        assert entry["actor_role"] == TEAM_LEAD
        assert entry["target_user_id"] == 101


def test_team_lead_analysis_routes_are_read_only() -> None:
    app = FastAPI()
    app.dependency_overrides[get_current_user] = _team_lead
    app.include_router(analysis_routes.router, prefix="/api/analysis")

    with TestClient(app) as client:
        response = client.post(
            "/api/analysis/ioc",
            json={"value": "198.51.100.10"},
        )

    assert response.status_code == 403


def test_cross_user_audit_schema_migration_preserves_existing_entries(tmp_path) -> None:
    db_path = tmp_path / "agent.db"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE agent_sessions (
                id TEXT PRIMARY KEY,
                goal TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                user_id INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE audit_log (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'system',
                action TEXT NOT NULL,
                action_type TEXT NOT NULL DEFAULT 'tool_call',
                requires_approval INTEGER NOT NULL DEFAULT 0,
                verdict TEXT,
                before_state TEXT,
                after_state TEXT,
                approved_by TEXT,
                status TEXT NOT NULL DEFAULT 'success',
                timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES agent_sessions(id)
            )
            """
        )
        connection.execute(
            "INSERT INTO agent_sessions (id, goal, status, created_at) VALUES (?, ?, ?, ?)",
            ("session-1", "old goal", "completed", "2026-01-01T00:00:00+00:00"),
        )
        connection.execute(
            """
            INSERT INTO audit_log
                (id, session_id, actor, action, action_type, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("audit-1", "session-1", "system", "tool", "tool_call", "2026-01-01T00:00:00+00:00"),
        )

    migration = _load_migration("005_add_cross_user_audit_fields.py")
    migration.migrate(str(db_path))

    with sqlite3.connect(str(db_path)) as connection:
        columns = {
            row[1]: row
            for row in connection.execute("PRAGMA table_info(audit_log)")
        }
        assert columns["actor_role"][3] == 0
        assert columns["target_user_id"][3] == 0
        assert columns["session_id"][3] == 0
        assert connection.execute(
            "SELECT id, session_id, action FROM audit_log"
        ).fetchall() == [("audit-1", "session-1", "tool")]

    store = AgentStore(str(db_path))
    entry_id = store.add_cross_user_read_audit(
        actor_user_id=900,
        actor_role=TEAM_LEAD,
        target_user_id=101,
        resource_type="analysis",
        resource_id="analysis-1",
    )
    assert any(entry["id"] == entry_id for entry in store.get_audit_log())
