"""History page visibility tests."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import page_auth
from src.web import app as web_app
from src.web.analysis_manager import AnalysisManager
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware


SOC = "SOC Analyst Tier 1-2"
TEAM_LEAD = "Team Lead"
ADMIN = "admin"


def _user(role: str, user_id: int) -> dict:
    return {
        "id": user_id,
        "email": f"user-{user_id}@example.test",
        "username": f"user-{user_id}",
        "role": role,
        "is_active": 1,
    }


def _page_app(tmp_path) -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / "analysis_jobs.db")
    )
    _register_page_routes(app)
    return app


def _seed_jobs(manager: AnalysisManager) -> None:
    manager.create_job("ioc", {"value": "analyst-target"}, user_id=101)
    manager.create_job("ioc", {"value": "other-target"}, user_id=202)
    manager.create_job("ioc", {"value": "outside-team-target"}, user_id=303)


def _client_for_page(app: FastAPI, monkeypatch, user: dict) -> TestClient:
    monkeypatch.setattr(
        page_auth,
        "get_current_user",
        lambda token, request=None: user,
    )
    client = TestClient(app)
    client.cookies.set("cabta_session", "test-token")
    return client


def test_analyst_history_page_contains_own_job_only(tmp_path, monkeypatch) -> None:
    app = _page_app(tmp_path)
    _seed_jobs(app.state.analysis_manager)

    with _client_for_page(app, monkeypatch, _user(SOC, 101)) as client:
        response = client.get("/history")

    assert response.status_code == 200
    assert "analyst-target" in response.text
    assert "other-target" not in response.text
    assert "outside-team-target" not in response.text


def test_admin_history_page_contains_all_jobs(tmp_path, monkeypatch) -> None:
    app = _page_app(tmp_path)
    _seed_jobs(app.state.analysis_manager)

    with _client_for_page(app, monkeypatch, _user(ADMIN, 900)) as client:
        response = client.get("/history")

    assert response.status_code == 200
    assert "analyst-target" in response.text
    assert "other-target" in response.text
    assert "outside-team-target" in response.text


def test_team_lead_history_page_contains_analyst_jobs_only(tmp_path, monkeypatch) -> None:
    app = _page_app(tmp_path)
    _seed_jobs(app.state.analysis_manager)
    monkeypatch.setattr(web_app, "get_user_ids_by_role", lambda role: [101, 202])

    with _client_for_page(app, monkeypatch, _user(TEAM_LEAD, 900)) as client:
        response = client.get("/history")

    assert response.status_code == 200
    assert "analyst-target" in response.text
    assert "other-target" in response.text
    assert "outside-team-target" not in response.text


def test_unauthenticated_history_page_keeps_normal_redirect(tmp_path) -> None:
    with TestClient(_page_app(tmp_path)) as client:
        response = client.get("/history", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Fhistory"
