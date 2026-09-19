from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.integrations.ticketing import create_incident_ticket, initialize_database
from src.web.auth import TEAM_LEAD, VALID_ROLES, get_current_user
from src.web.routes import analysis as analysis_routes
from src.web.routes import tickets as tickets_routes
from src.tools import ioc_investigator as ioc_module


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "src" / "db" / "migrations" / "011_add_ticket_owner.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("migration_011", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tickets_app(user: dict | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(tickets_routes.router, prefix="/api")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _seed_tickets(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "tickets.db"
    monkeypatch.setenv("TICKETING_DB_PATH", str(db_path))
    initialize_database()
    result = {"ioc": "198.51.100.1", "verdict": "MALICIOUS"}
    create_incident_ticket(result, "owner-12", owner_id=12)
    create_incident_ticket(result, "owner-34", owner_id=34)
    create_incident_ticket(result, "legacy-ownerless")


def test_ticket_owner_migration_adds_nullable_column_and_index_idempotently(tmp_path):
    db_path = tmp_path / "legacy-tickets.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT NOT NULL UNIQUE,
                analysis_id TEXT NOT NULL,
                ioc TEXT NOT NULL,
                verdict TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                summary TEXT,
                recommendations TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO tickets (ticket_id, analysis_id, ioc, verdict, status, created_at) "
            "VALUES ('legacy', 'legacy-analysis', '8.8.8.8', 'MALICIOUS', 'open', 'now')"
        )

    migration = _load_migration()
    migration.migrate(db_path)
    migration.migrate(db_path)

    with sqlite3.connect(db_path) as connection:
        columns = {row[1]: row for row in connection.execute("PRAGMA table_info(tickets)")}
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(tickets)")}
        assert "owner_id" in columns
        assert columns["owner_id"][3] == 0  # nullable
        assert "idx_tickets_owner_id" in indexes
        assert connection.execute(
            "SELECT owner_id FROM tickets WHERE ticket_id = 'legacy'"
        ).fetchone() == (None,)


def test_tickets_api_requires_authentication():
    with TestClient(_tickets_app()) as client:
        response = client.get("/api/tickets")

    assert response.status_code == 401


@pytest.mark.parametrize("role", sorted(VALID_ROLES))
def test_tickets_api_all_authenticated_roles_can_read(role, monkeypatch, tmp_path):
    _seed_tickets(monkeypatch, tmp_path)
    user = {
        "id": 12,
        "email": "reader@example.test",
        "username": "reader",
        "role": role,
        "is_active": 1,
    }

    with TestClient(_tickets_app(user)) as client:
        response = client.get("/api/tickets")

    assert response.status_code == 200


@pytest.mark.parametrize("role", [
    "SOC Analyst Tier 1-2", "Incident Responder", "Threat Hunter",
])
def test_tickets_api_scoped_roles_see_only_owned_nonlegacy_rows(role, monkeypatch, tmp_path):
    _seed_tickets(monkeypatch, tmp_path)
    user = {
        "id": 12,
        "email": "reader@example.test",
        "username": "reader",
        "role": role,
        "is_active": 1,
    }

    with TestClient(_tickets_app(user)) as client:
        response = client.get("/api/tickets")

    assert response.status_code == 200
    assert [row["analysis_id"] for row in response.json()["tickets"]] == ["owner-12"]


@pytest.mark.parametrize("role", [TEAM_LEAD, "admin"])
def test_tickets_api_team_lead_and_admin_see_all_rows_including_legacy(role, monkeypatch, tmp_path):
    _seed_tickets(monkeypatch, tmp_path)
    user = {
        "id": 12,
        "email": "reader@example.test",
        "username": "reader",
        "role": role,
        "is_active": 1,
    }

    with TestClient(_tickets_app(user)) as client:
        response = client.get("/api/tickets")

    assert response.status_code == 200
    assert {row["analysis_id"] for row in response.json()["tickets"]} == {
        "owner-12", "owner-34", "legacy-ownerless",
    }


def test_ioc_background_passes_job_owner_to_investigator(monkeypatch):
    calls = {}

    class FakeInvestigator:
        def __init__(self, config, notification_manager=None):
            pass

        def set_progress_callback(self, callback):
            pass

        async def investigate(self, value, analysis_id=None, user_id=None):
            calls.update(value=value, analysis_id=analysis_id, user_id=user_id)
            return {"verdict": "CLEAN", "threat_score": 0}

    monkeypatch.setattr(analysis_routes, "_load_config", lambda: {})
    monkeypatch.setattr("src.tools.ioc_investigator.IOCInvestigator", FakeInvestigator)
    manager = MagicMock()

    analysis_routes._run_ioc_analysis_bg(
        manager, "job-123", "8.8.8.8", "ip", user_id=42,
    )

    assert calls == {"value": "8.8.8.8", "analysis_id": "job-123", "user_id": 42}
    manager.complete_job.assert_called_once()


async def test_ioc_investigator_persists_explicit_owner_id(monkeypatch):
    investigator = object.__new__(ioc_module.IOCInvestigator)
    investigator.config = {
        "analysis": {"enable_llm": False},
        "ticketing": {"create_on_verdict": ["MALICIOUS"]},
    }
    investigator.notification_manager = None
    investigator.rag_kb = None
    investigator.threat_intel = MagicMock()
    investigator.threat_intel.investigate_ioc_comprehensive = AsyncMock(
        return_value={"sources": {}, "sources_checked": 1, "sources_flagged": 1}
    )
    investigator._trusted_infrastructure_match = lambda *_args: None
    investigator._aggregate_seen_dates = lambda *_args: (None, None)
    investigator._extract_malware_family = lambda *_args: None
    investigator._generate_recommendations = lambda *_args: []

    monkeypatch.setattr(ioc_module.IntelligentScoring, "calculate_ioc_score", lambda *_: 90)
    monkeypatch.setattr(ioc_module.IntelligentScoring, "calculate_source_coverage", lambda *_: 1)
    monkeypatch.setattr(ioc_module, "determine_verdict", lambda *_: "MALICIOUS")
    monkeypatch.setattr(ioc_module.RuleGenerator, "generate_ioc_rules", lambda *_: {})
    create_ticket = MagicMock()
    monkeypatch.setattr(ioc_module, "create_incident_ticket", create_ticket)

    await investigator.investigate("8.8.8.8", analysis_id="job-321", user_id=77)

    create_ticket.assert_called_once()
    assert create_ticket.call_args.args[1] == "job-321"
    assert create_ticket.call_args.kwargs["owner_id"] == 77


def test_file_background_passes_job_and_owner_to_analyzer(monkeypatch):
    call = {}

    class FakeMalwareAnalyzer:
        def __init__(self, config, notification_manager=None):
            pass

        async def analyze(self, file_path, analysis_id=None, user_id=None):
            call.update(file_path=file_path, analysis_id=analysis_id, user_id=user_id)
            return {"verdict": "CLEAN", "threat_score": 0}

    monkeypatch.setattr(analysis_routes, "_load_config", lambda: {})
    monkeypatch.setattr("src.tools.malware_analyzer.MalwareAnalyzer", FakeMalwareAnalyzer)
    manager = MagicMock()

    analysis_routes._run_file_analysis_bg(
        manager, "file-job", "sample.bin", user_id=51,
    )

    assert call == {"file_path": "sample.bin", "analysis_id": "file-job", "user_id": 51}
    manager.complete_job.assert_called_once()


def test_email_background_passes_job_and_owner_to_analyzer(monkeypatch):
    call = {}

    class FakeEmailAnalyzer:
        def __init__(self, config):
            pass

        async def analyze(self, email_path, analysis_id=None, user_id=None):
            call.update(email_path=email_path, analysis_id=analysis_id, user_id=user_id)
            return {"verdict": "CLEAN", "base_phishing_score": 0}

    monkeypatch.setattr(analysis_routes, "_load_config", lambda: {})
    monkeypatch.setattr("src.tools.email_analyzer.EmailAnalyzer", FakeEmailAnalyzer)
    manager = MagicMock()

    analysis_routes._run_email_analysis_bg(
        manager, "email-job", "message.eml", user_id=63,
    )

    assert call == {"email_path": "message.eml", "analysis_id": "email-job", "user_id": 63}
    manager.complete_job.assert_called_once()
