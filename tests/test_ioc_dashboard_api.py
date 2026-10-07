"""Read-only IOC dashboard statistics API tests."""

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.analysis_manager import AnalysisManager
from src.web.auth import get_current_user
from src.web.routes import analysis as analysis_routes


def _analyst(user_id=101):
    return {
        "id": user_id,
        "email": f"analyst-{user_id}@example.test",
        "username": f"analyst-{user_id}",
        "role": "SOC Analyst Tier 1-2",
        "is_active": 1,
    }


def _dashboard_app(tmp_path, user=None):
    app = FastAPI()
    app.state.analysis_manager = AnalysisManager(str(tmp_path / "analysis.db"))
    app.include_router(analysis_routes.router, prefix="/api/analysis")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _set_created_at(manager, job_id, value):
    conn = manager._connect()
    conn.execute("UPDATE analysis_jobs SET created_at = ? WHERE id = ?", (value, job_id))
    conn.commit()
    conn.close()


def test_dashboard_stats_group_verdicts_and_exclude_missing_dates_from_chart(tmp_path):
    app = _dashboard_app(tmp_path, _analyst())
    manager = app.state.analysis_manager
    current = datetime.now(timezone.utc).isoformat()
    jobs = [
        manager.create_job("ioc", {"value": "bad.example"}, user_id=101),
        manager.create_job("ioc", {"value": "maybe.example"}, user_id=101),
        manager.create_job("ioc", {"value": "good.example"}, user_id=101),
        manager.create_job("ioc", {"value": "unknown.example"}, user_id=101),
        manager.create_job("ioc", {"value": "queued.example"}, user_id=101),
    ]
    manager.complete_job(jobs[0], {"private": "must not leak"}, verdict="MALICIOUS", score=92)
    manager.complete_job(jobs[1], {}, verdict="SUSPICIOUS", score=54)
    manager.complete_job(jobs[2], {}, verdict="CLEAN", score=2)
    manager.complete_job(jobs[3], {}, verdict="UNKNOWN", score=0)
    for job_id in jobs[:4]:
        _set_created_at(manager, job_id, current)
    _set_created_at(manager, jobs[3], "")

    with TestClient(app) as client:
        response = client.get("/api/analysis/dashboard/stats?utc_offset_minutes=0")

    assert response.status_code == 200
    payload = response.json()
    assert (payload["total"], payload["malicious"], payload["suspicious"], payload["clean"], payload["other"]) == (5, 1, 1, 1, 2)
    assert sum(sum(day[key] for key in ("malicious", "suspicious", "clean", "other")) for day in payload["daily"]) == 4
    assert [item["indicator"] for item in payload["feed"]] == ["bad.example"]
    assert payload["feed"][0]["score"] == 92
    assert "private" not in str(payload)
    assert "result" not in payload["feed"][0]


def test_dashboard_stats_are_scoped_to_authenticated_analyst(tmp_path):
    app = _dashboard_app(tmp_path, _analyst(101))
    manager = app.state.analysis_manager
    own = manager.create_job("ioc", {"value": "own.example"}, user_id=101)
    other = manager.create_job("ioc", {"value": "other.example"}, user_id=202)
    manager.complete_job(own, {}, verdict="MALICIOUS", score=80)
    manager.complete_job(other, {}, verdict="MALICIOUS", score=99)

    with TestClient(app) as client:
        response = client.get("/api/analysis/dashboard/stats")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert [item["indicator"] for item in response.json()["feed"]] == ["own.example"]


def test_team_lead_dashboard_feed_is_audited_and_hides_owner_id(tmp_path, monkeypatch):
    from src.web.auth import TEAM_LEAD

    app = _dashboard_app(tmp_path, {**_analyst(900), "role": TEAM_LEAD})
    manager = app.state.analysis_manager
    job_id = manager.create_job("ioc", {"value": "team-target.example"}, user_id=101)
    manager.complete_job(job_id, {}, verdict="MALICIOUS", score=87)
    audit = []
    app.state.agent_store = SimpleNamespace(
        add_cross_user_read_audit=lambda **entry: audit.append(entry) or "audit-id"
    )
    monkeypatch.setattr(analysis_routes, "get_user_ids_by_role", lambda _role: [101])

    with TestClient(app) as client:
        response = client.get("/api/analysis/dashboard/stats")

    assert response.status_code == 200
    assert len(audit) == 1
    assert audit[0]["resource_type"] == "analysis"
    assert audit[0]["resource_id"] == job_id
    assert audit[0]["target_user_id"] == 101
    assert "user_id" not in response.json()["feed"][0]
