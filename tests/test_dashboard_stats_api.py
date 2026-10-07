from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.analysis_manager import AnalysisManager
from src.web.auth import get_current_user
from src.web.routes import dashboard as dashboard_routes


def _seed_job(manager: AnalysisManager, verdict: str, score, created_at: str) -> None:
    job_id = manager.create_job(
        "ioc",
        {"value": f"indicator-{verdict}-{score}", "ioc_type": "ip"},
        user_id=909,
    )
    manager.complete_job(job_id, {}, verdict=verdict, score=score)
    conn = manager._connect()
    try:
        conn.execute(
            "UPDATE analysis_jobs SET created_at = ? WHERE id = ?",
            (created_at, job_id),
        )
        conn.commit()
    finally:
        conn.close()


def _stats_client(manager: AnalysisManager, role: str) -> TestClient:
    app = FastAPI()
    app.state.analysis_manager = manager
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 101,
        "email": "dashboard@example.test",
        "username": "dashboard-user",
        "role": role,
        "is_active": 1,
    }
    app.include_router(dashboard_routes.router, prefix="/api/dashboard")
    return TestClient(app)


@pytest.fixture
def seeded_manager(tmp_path) -> tuple[AnalysisManager, datetime]:
    manager = AnalysisManager(str(tmp_path / "dashboard-jobs.db"))
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    _seed_job(manager, "MALICIOUS", 100, f"{today.isoformat()}T06:50:00+00:00")
    _seed_job(manager, "PHISHING", 20, f"{today.isoformat()}T07:00:00Z")
    _seed_job(manager, "SUSPICIOUS", 21, f"{today.isoformat()}T08:00:00Z")
    _seed_job(manager, "SPAM", 60, f"{yesterday.isoformat()}T09:00:00Z")
    _seed_job(manager, "CLEAN", 81, f"{today.isoformat()}T10:00:00Z")
    _seed_job(manager, "UNKNOWN", None, f"{today.isoformat()}T11:00:00Z")
    _seed_job(manager, "MALICIOUS", 40, "")
    _seed_job(manager, "CLEAN", 101, f"{today.isoformat()}T12:00:00Z")
    _seed_job(manager, "SPAM", -1, "not-a-date")
    return manager, datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc)


def test_dashboard_stats_additive_verdict_daily_and_score_aggregations(seeded_manager) -> None:
    manager, today = seeded_manager
    with _stats_client(manager, "SOC Analyst Tier 1-2") as client:
        response = client.get("/api/dashboard/stats")

    assert response.status_code == 200
    payload = response.json()
    assert {
        key: payload[key]
        for key in (
            "total_analyses", "malicious_count", "suspicious_count", "clean_count",
        )
    } == {
        "total_analyses": 9,
        "malicious_count": 2,
        "suspicious_count": 1,
        "clean_count": 2,
    }
    assert payload["phishing_count"] == 1
    assert payload["spam_count"] == 2
    assert payload["unknown_count"] == 1
    assert payload["average_score"] == 52.8

    daily = payload["daily_counts"]
    assert len(daily) == 14
    assert daily[0]["date"] == (today.date() - timedelta(days=13)).isoformat()
    assert daily[-1]["date"] == today.date().isoformat()
    today_bucket = next(row for row in daily if row["date"] == today.date().isoformat())
    yesterday_bucket = next(row for row in daily if row["date"] == (today.date() - timedelta(days=1)).isoformat())
    assert {key: today_bucket[key] for key in ("malicious", "suspicious", "clean")} == {
        "malicious": 2,
        "suspicious": 1,
        "clean": 2,
    }
    assert {key: yesterday_bucket[key] for key in ("malicious", "suspicious", "clean")} == {
        "malicious": 0,
        "suspicious": 1,
        "clean": 0,
    }
    assert sum(sum(row[key] for key in ("malicious", "suspicious", "clean")) for row in daily) == 6

    assert payload["score_buckets"] == [
        {"label": "0-20", "count": 1},
        {"label": "21-40", "count": 2},
        {"label": "41-60", "count": 1},
        {"label": "61-80", "count": 0},
        {"label": "81-100", "count": 2},
    ]
    assert "user_id" not in response.text


@pytest.mark.parametrize(
    "role",
    ["SOC Analyst Tier 1-2", "Incident Responder", "Threat Hunter", "Team Lead", "admin"],
)
def test_dashboard_stats_new_keys_keep_existing_role_access(seeded_manager, role: str) -> None:
    manager, _today = seeded_manager
    with _stats_client(manager, role) as client:
        response = client.get("/api/dashboard/stats")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total_analyses"] == 9
    assert "daily_counts" in payload
    assert "score_buckets" in payload
    assert "user_id" not in payload


def test_dashboard_stats_still_denies_unlisted_roles(seeded_manager) -> None:
    manager, _today = seeded_manager
    with _stats_client(manager, "Viewer") as client:
        response = client.get("/api/dashboard/stats")
    assert response.status_code == 403
