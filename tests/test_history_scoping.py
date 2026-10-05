"""History page visibility tests."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import page_auth
from src.web import app as web_app
from src.web.analysis_manager import AnalysisManager
from src.web.auth import get_current_user
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from src.web.routes import analysis as analysis_routes


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


def _summary_app(tmp_path, user: dict | None = None) -> FastAPI:
    app = _page_app(tmp_path)
    app.include_router(analysis_routes.router, prefix="/api/analysis")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _seed_summary_jobs(manager: AnalysisManager) -> None:
    for user_id, prefix in ((101, "analyst-a"), (202, "analyst-b"), (303, "team-lead")):
        phishing = manager.create_job("email", {"filename": f"{prefix}-phishing.eml"}, user_id=user_id)
        spam = manager.create_job("email", {"filename": f"{prefix}-spam.eml"}, user_id=user_id)
        failed = manager.create_job("file", {"filename": f"{prefix}-failed.bin"}, user_id=user_id)
        manager.create_job("ioc", {"value": f"{prefix}-queued"}, user_id=user_id)
        manager.complete_job(phishing, {}, verdict="PHISHING", score=90)
        manager.complete_job(spam, {}, verdict="SPAM", score=60)
        manager.fail_job(failed, "timeout")

    clean = manager.create_job("file", {"filename": "analyst-a-clean.txt"}, user_id=101)
    unknown = manager.create_job("ioc", {"value": "analyst-a-unknown"}, user_id=101)
    manager.complete_job(clean, {}, verdict="CLEAN", score=5)
    manager.complete_job(unknown, {}, verdict="UNKNOWN", score=0)


def _assert_summary_shape(response, expected: dict) -> None:
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {
        "total",
        "malicious",
        "suspicious",
        "clean",
        "unknown",
        "failed",
        "in_progress",
    }
    assert "analysis_type" not in payload
    assert payload == expected


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


def test_history_summary_admin_sees_all_users(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(ADMIN, 900))
    _seed_summary_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        response = client.get("/api/analysis/history/summary")

    _assert_summary_shape(
        response,
        {
            "total": 14,
            "malicious": 3,
            "suspicious": 3,
            "clean": 1,
            "unknown": 1,
            "failed": 3,
            "in_progress": 3,
        },
    )


def test_history_summary_team_lead_sees_analysts_only(tmp_path, monkeypatch) -> None:
    app = _summary_app(tmp_path, _user(TEAM_LEAD, 303))
    _seed_summary_jobs(app.state.analysis_manager)
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda role: [101, 202])

    with TestClient(app) as client:
        response = client.get("/api/analysis/history/summary")

    # Mirrors /api/analysis/history/: Team Leads see analyst jobs, not their own jobs.
    _assert_summary_shape(
        response,
        {
            "total": 10,
            "malicious": 2,
            "suspicious": 2,
            "clean": 1,
            "unknown": 1,
            "failed": 2,
            "in_progress": 2,
        },
    )


def test_history_summary_analyst_sees_own_jobs_only(tmp_path) -> None:
    app = _summary_app(tmp_path, _user(SOC, 101))
    _seed_summary_jobs(app.state.analysis_manager)

    with TestClient(app) as client:
        response = client.get("/api/analysis/history/summary")

    _assert_summary_shape(
        response,
        {
            "total": 6,
            "malicious": 1,
            "suspicious": 1,
            "clean": 1,
            "unknown": 1,
            "failed": 1,
            "in_progress": 1,
        },
    )


def test_history_summary_unauthenticated_gets_normal_api_denial(tmp_path) -> None:
    with TestClient(_summary_app(tmp_path)) as client:
        response = client.get("/api/analysis/history/summary")

    assert response.status_code == 401
