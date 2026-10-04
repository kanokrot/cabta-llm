from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.email_capabilities import clear_email_capability_cache
from src.web.routes import analysis as analysis_routes


def _app(user=None):
    app = FastAPI()
    app.include_router(analysis_routes.router, prefix="/api/analysis")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _user(role):
    return {
        "id": 1,
        "email": "capability@example.test",
        "username": "capability-user",
        "role": role,
        "is_active": 1,
    }


def setup_function():
    clear_email_capability_cache()


def test_returns_all_capabilities_and_allowed_statuses(monkeypatch):
    class FakeAnalyzer:
        file_analyzer = None
        ioc_investigator = None

    monkeypatch.setattr(
        "src.web.email_capabilities.create_route_email_analyzer",
        lambda: FakeAnalyzer(),
    )
    response = TestClient(_app(_user("admin"))).get("/api/analysis/email/capabilities")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["capabilities"]) == 11
    assert {item["key"] for item in payload["capabilities"]} == {
        "spf_dkim_dmarc",
        "header_forensics",
        "url_analysis",
        "attachment_scanning",
        "brand_impersonation",
        "openphish_url",
        "malwarebazaar_hash",
        "sender_domain_whois",
        "lookalike_domains",
        "hudsonrock_breach",
        "paste_monitoring",
    }
    assert {item["status"] for item in payload["capabilities"]} <= {
        "active",
        "limited",
        "not_connected",
        "needs_config",
        "unreachable",
    }


def test_unconnected_analyzer_dependencies_are_not_connected(monkeypatch):
    class FakeAnalyzer:
        file_analyzer = None
        ioc_investigator = None

    monkeypatch.setattr(
        "src.web.email_capabilities.create_route_email_analyzer",
        lambda: FakeAnalyzer(),
    )
    response = TestClient(_app(_user("admin"))).get("/api/analysis/email/capabilities")
    by_key = {item["key"]: item for item in response.json()["capabilities"]}

    assert by_key["attachment_scanning"]["status"] == "not_connected"
    assert by_key["sender_domain_whois"]["status"] == "not_connected"
    assert by_key["malwarebazaar_hash"]["status"] == "not_connected"


def test_non_admin_does_not_see_reasons(monkeypatch):
    class FakeAnalyzer:
        file_analyzer = None
        ioc_investigator = None

    monkeypatch.setattr(
        "src.web.email_capabilities.create_route_email_analyzer",
        lambda: FakeAnalyzer(),
    )
    response = TestClient(_app(_user("SOC Analyst Tier 1-2"))).get(
        "/api/analysis/email/capabilities"
    )

    assert response.status_code == 200
    assert all("reason" not in item for item in response.json()["capabilities"])


def test_admin_sees_reasons(monkeypatch):
    class FakeAnalyzer:
        file_analyzer = None
        ioc_investigator = None

    monkeypatch.setattr(
        "src.web.email_capabilities.create_route_email_analyzer",
        lambda: FakeAnalyzer(),
    )
    response = TestClient(_app(_user("admin"))).get("/api/analysis/email/capabilities")

    assert response.status_code == 200
    assert all("reason" in item for item in response.json()["capabilities"])


def test_unauthenticated_request_is_rejected():
    response = TestClient(_app()).get("/api/analysis/email/capabilities")
    assert response.status_code == 401


def test_cache_does_not_create_analyzer_twice(monkeypatch):
    class FakeAnalyzer:
        file_analyzer = None
        ioc_investigator = None

    calls = {"count": 0}

    def factory():
        calls["count"] += 1
        return FakeAnalyzer()

    monkeypatch.setattr(
        "src.web.email_capabilities.create_route_email_analyzer",
        factory,
    )
    client = TestClient(_app(_user("admin")))
    first = client.get("/api/analysis/email/capabilities")
    second = client.get("/api/analysis/email/capabilities")

    assert first.status_code == second.status_code == 200
    assert calls["count"] == 1


def test_non_admin_cannot_refresh(monkeypatch):
    response = TestClient(_app(_user("SOC Analyst Tier 1-2"))).get(
        "/api/analysis/email/capabilities?refresh=1"
    )
    assert response.status_code == 403
