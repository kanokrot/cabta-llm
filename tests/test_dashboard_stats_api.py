from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.analysis_manager import AnalysisManager
from src.web.auth import get_current_user
from src.web.routes import dashboard as dashboard_routes


def _seed_job(
    manager: AnalysisManager,
    verdict: str,
    score,
    created_at: str,
    *,
    indicator: str | None = None,
    result: dict | None = None,
) -> str:
    job_id = manager.create_job(
        "ioc",
        {"value": indicator or f"indicator-{verdict}-{score}", "ioc_type": "ip"},
        user_id=909,
    )
    manager.complete_job(job_id, result or {}, verdict=verdict, score=score)
    conn = manager._connect()
    try:
        conn.execute(
            "UPDATE analysis_jobs SET created_at = ? WHERE id = ?",
            (created_at, job_id),
        )
        conn.commit()
    finally:
        conn.close()
    return job_id


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
    assert payload["country_covered"] == 0
    assert payload["country_stats"] == []
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
    assert "country_stats" in payload
    assert "country_covered" in payload
    assert "user_id" not in payload


def test_dashboard_stats_still_denies_unlisted_roles(seeded_manager) -> None:
    manager, _today = seeded_manager
    with _stats_client(manager, "Viewer") as client:
        response = client.get("/api/dashboard/stats")
    assert response.status_code == 403


def test_dashboard_country_stats_count_unique_ips_and_worst_verdict(seeded_manager) -> None:
    manager, _today = seeded_manager
    timestamp = "2026-10-01T00:00:00+00:00"
    common = {"ioc_type": "ipv4"}
    _seed_job(
        manager, "MALICIOUS", 90, timestamp, indicator="8.8.8.8",
        result={**common, "ioc": "8.8.8.8", "country_code": "us"},
    )
    _seed_job(
        manager, "SUSPICIOUS", 55, timestamp, indicator="8.8.8.8",
        result={**common, "ioc": "8.8.8.8", "country_code": "US"},
    )
    _seed_job(
        manager, "CLEAN", 5, timestamp, indicator="1.1.1.1",
        result={**common, "ioc": "1.1.1.1", "country_code": "US"},
    )
    _seed_job(
        manager, "PHISHING", 85, timestamp, indicator="9.9.9.9",
        result={**common, "ioc": "9.9.9.9", "country_code": "US"},
    )
    for verdict, score in (("CLEAN", 10), ("PHISHING", 80), ("SPAM", 60), ("UNKNOWN", 0)):
        _seed_job(
            manager, verdict, score, timestamp, indicator="8.8.8.8",
            result={**common, "ioc": "8.8.8.8", "country_code": "CA"},
        )
    for verdict, score in (("CLEAN", 10), ("SUSPICIOUS", 55)):
        _seed_job(
            manager, verdict, score, timestamp, indicator="2.2.2.2",
            result={**common, "ioc": "2.2.2.2", "country_code": "DE"},
        )
    _seed_job(
        manager, "MALICIOUS", 99, timestamp, indicator="4.4.4.4",
        result={**common, "ioc": "4.4.4.4"},
    )
    bad_json_id = _seed_job(
        manager, "MALICIOUS", 99, timestamp, indicator="5.5.5.5",
        result={**common, "ioc": "5.5.5.5", "country_code": "AU"},
    )
    _seed_job(
        manager, "MALICIOUS", 99, timestamp, indicator="6.6.6.6",
        result={**common, "ioc": "6.6.6.6", "country_code": "AUS"},
    )
    conn = manager._connect()
    try:
        conn.execute("UPDATE analysis_jobs SET result = ? WHERE id = ?", ("not-json", bad_json_id))
        conn.commit()
    finally:
        conn.close()

    with _stats_client(manager, "SOC Analyst Tier 1-2") as client:
        response = client.get("/api/dashboard/stats")

    assert response.status_code == 200
    payload = response.json()
    assert payload["country_covered"] == 10
    assert payload["country_stats"] == [
        {"code": "US", "ips": 3, "analyses": 4, "worst_verdict": "MALICIOUS"},
        {"code": "CA", "ips": 1, "analyses": 4, "worst_verdict": "CLEAN"},
        {"code": "DE", "ips": 1, "analyses": 2, "worst_verdict": "SUSPICIOUS"},
    ]
    assert all(ip not in response.text for ip in (
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4", "5.5.5.5", "6.6.6.6", "2.2.2.2",
    ))
    assert "909" not in response.text
    assert "AUS" not in {item["code"] for item in payload["country_stats"]}
