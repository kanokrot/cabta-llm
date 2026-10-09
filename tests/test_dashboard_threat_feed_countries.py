from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.integrations import threat_feed_sync as feeds
from src.web.auth import get_current_user
from src.web.routes import dashboard


def _client(tmp_path, role="SOC Analyst Tier 1-2", authenticated=True):
    app = FastAPI()
    app.state.threat_feed_db_path = tmp_path / "feed.db"
    if authenticated:
        app.dependency_overrides[get_current_user] = lambda: {
            "id": 7, "email": "feed@test", "username": "feed", "role": role, "is_active": 1,
        }
    app.include_router(dashboard.router, prefix="/api/dashboard")
    return TestClient(app)


def _feodo(ip, country, malware, status):
    return {
        "ip_address": ip,
        "port": 443,
        "country": country,
        "malware": malware,
        "status": status,
        "first_seen": "2026-10-08 00:00:00",
        "last_online": "2026-10-09",
    }


def test_threat_feed_countries_combines_sources_and_preserves_unknown_online_count(tmp_path):
    db = tmp_path / "feed.db"
    rows, _skipped = feeds.normalize_feodo([
        _feodo("1.2.3.4", "us", "QakBot", "online"),
        _feodo("1.2.3.5", "US", "QakBot", "offline"),
        _feodo("1.2.3.6", "US", "Emotet", "offline"),
        _feodo("1.2.3.7", "GB", "Emotet", "online"),
        _feodo("1.2.3.8", "", "Ignored", "online"),
    ], "2026-10-09T12:00:00+00:00")
    feeds._store_success(db, "feodo", rows, "2026-10-09T12:00:00+00:00")
    threatfox, _skipped = feeds.normalize_threatfox({
        "query_status": "ok",
        "data": [
            {"ioc": "8.8.8.8:80", "ioc_type": "ipv4:port", "country": "us", "malware_printable": "QakBot"},
            {"ioc": "8.8.8.9:80", "ioc_type": "ipv4:port", "country": "US", "malware_printable": "Emotet"},
            {"ioc": "9.9.9.9:80", "ioc_type": "ipv4:port", "country": "GB", "malware_printable": "Emotet"},
            {"ioc": "1.1.1.1:80", "ioc_type": "ipv4:port", "country": "JP", "malware_printable": "Bot"},
            {"ioc": "example.test", "ioc_type": "domain", "country": "FR", "malware_printable": "Ignored"},
        ],
    }, "2026-10-09T12:00:00+00:00")
    feeds._store_success(db, "threatfox", threatfox, "2026-10-09T12:00:00+00:00")

    with _client(tmp_path) as client:
        response = client.get("/api/dashboard/threat-feed/countries")

    assert response.status_code == 200
    assert response.json() == {"countries": [
        {"code": "US", "count": 5, "online_count": 1, "feodo_count": 3, "threatfox_count": 2, "top_malware": "QakBot"},
        {"code": "GB", "count": 2, "online_count": 1, "feodo_count": 1, "threatfox_count": 1, "top_malware": "Emotet"},
        {"code": "JP", "count": 1, "online_count": None, "feodo_count": 0, "threatfox_count": 1, "top_malware": "Bot"},
    ]}


def test_threat_feed_countries_empty_table_and_role_guard(tmp_path):
    with _client(tmp_path) as client:
        response = client.get("/api/dashboard/threat-feed/countries")
    assert response.status_code == 200
    assert response.json() == {"countries": []}

    with _client(tmp_path, role="Viewer") as denied:
        assert denied.get("/api/dashboard/threat-feed/countries").status_code == 403

    with _client(tmp_path, authenticated=False) as anonymous:
        assert anonymous.get("/api/dashboard/threat-feed/countries").status_code in {401, 403}
