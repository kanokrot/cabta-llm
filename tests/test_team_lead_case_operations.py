"""Phase 3 Team Lead case operations and escalation coverage."""

from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import TEAM_LEAD, get_current_user
from src.web.case_store import CaseStore
from src.web.routes import agent as agent_routes
from src.web.routes import cases as cases_routes
from src.web.routes import reports as reports_routes


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


def test_team_lead_can_update_priority_and_reassign_case(tmp_path, monkeypatch) -> None:
    store = CaseStore(str(tmp_path / "cases.db"))
    case_id = store.create_case("Escalate suspicious IOC")

    assigned_users = {
        201: {"id": 201, "role": "Incident Responder", "is_active": 1},
        202: {"id": 202, "role": "Threat Hunter", "is_active": 1},
    }
    monkeypatch.setattr(
        cases_routes,
        "get_active_user",
        lambda user_id: assigned_users.get(user_id),
    )

    app = FastAPI()
    app.state.case_store = store
    app.dependency_overrides[get_current_user] = _team_lead
    app.include_router(cases_routes.router, prefix="/api/cases")

    with TestClient(app) as client:
        response = client.patch(
            f"/api/cases/{case_id}",
            json={"priority": "critical", "assignee": 201},
        )
        assert response.status_code == 200
        assert response.json()["priority"] == "critical"
        assert response.json()["assignee"] == 201

        response = client.patch(
            f"/api/cases/{case_id}",
            json={"assignee": 202},
        )

    assert response.status_code == 200
    assert response.json()["assignee"] == 202
    assert store.get_case(case_id)["priority"] == "critical"


def test_case_operation_rejects_non_escalation_assignee(tmp_path, monkeypatch) -> None:
    store = CaseStore(str(tmp_path / "cases.db"))
    case_id = store.create_case("Reject invalid assignee")
    monkeypatch.setattr(
        cases_routes,
        "get_active_user",
        lambda _user_id: {"id": 301, "role": "SOC Analyst Tier 1-2", "is_active": 1},
    )

    app = FastAPI()
    app.state.case_store = store
    app.dependency_overrides[get_current_user] = _team_lead
    app.include_router(cases_routes.router, prefix="/api/cases")

    with TestClient(app) as client:
        response = client.patch(
            f"/api/cases/{case_id}",
            json={"assignee": 301},
        )

    assert response.status_code == 422
    assert store.get_case(case_id)["assignee"] is None


def test_team_lead_can_approve_but_cannot_edit_or_deploy_rule(monkeypatch) -> None:
    app = FastAPI()
    app.state.analysis_manager = type(
        "Manager",
        (),
        {
            "get_job": lambda _self, _analysis_id: {
                "id": "analysis-phase3",
                "result": {"detection_rules": {"kql": "DeviceProcessEvents"}},
            },
            "update_detection_rule": lambda *_args: True,
        },
    )()
    app.dependency_overrides[get_current_user] = _team_lead
    monkeypatch.setattr(
        reports_routes,
        "validate_rule",
        lambda *_args: {"valid": True},
    )
    app.include_router(reports_routes.router, prefix="/api/reports")

    with TestClient(app) as client:
        approval = client.post(
            "/api/reports/analysis-phase3/rules/kql/approve",
            json={"approved_by": "team-lead"},
        )
        edit = client.put(
            "/api/reports/analysis-phase3/rules/kql",
            json={"content": "DeviceProcessEvents"},
        )
        deploy = client.post(
            "/api/reports/analysis-phase3/rules/kql/mark-deployed",
            json={},
        )

    assert approval.status_code == 200
    assert edit.status_code == 403
    assert deploy.status_code == 403


def test_team_lead_cannot_call_agent_dangerous_tool_routes() -> None:
    app = FastAPI()
    app.dependency_overrides[get_current_user] = _team_lead
    app.include_router(agent_routes.router, prefix="/api/agent")

    with TestClient(app) as client:
        response = client.get("/api/agent/tools?category=sandbox")

    assert response.status_code == 403


def test_case_operations_migration_preserves_data_and_is_idempotent(tmp_path) -> None:
    db_path = tmp_path / "legacy-cases.db"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'Open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO cases
                (id, title, description, severity, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "case-1",
                "Existing case",
                "preserve me",
                "high",
                "Open",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    migration = _load_migration("006_add_case_operations.py")
    migration.migrate(str(db_path))
    migration.migrate(str(db_path))

    with sqlite3.connect(str(db_path)) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(cases)").fetchall()
        }
        assert {"assignee", "priority"}.issubset(columns)
        assert connection.execute(
            "SELECT id, title, severity, assignee, priority FROM cases"
        ).fetchall() == [("case-1", "Existing case", "high", None, "medium")]

    store = CaseStore(str(db_path))
    assert store.get_case("case-1")["title"] == "Existing case"
