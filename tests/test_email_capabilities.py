from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.email_capabilities import clear_email_capability_cache
from src.web.routes import analysis as analysis_routes


class FakeAnalyzer:
    def __init__(self, file_analyzer=None, ioc_investigator=None):
        self.file_analyzer = file_analyzer
        self.ioc_investigator = ioc_investigator


class FakeThreatIntel:
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}


class FakeIOCInvestigator:
    def __init__(self, api_keys=None):
        self.threat_intel = FakeThreatIntel(api_keys)


def _app(user=None, analyzer=None):
    app = FastAPI()
    app.state.email_analyzer = analyzer
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


def test_returns_all_capabilities_and_allowed_statuses():
    response = TestClient(_app(_user("admin"), FakeAnalyzer())).get(
        "/api/analysis/email/capabilities"
    )

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


def test_unconnected_analyzer_dependencies_are_not_connected():
    response = TestClient(_app(_user("admin"), FakeAnalyzer())).get(
        "/api/analysis/email/capabilities"
    )
    by_key = {item["key"]: item for item in response.json()["capabilities"]}

    assert by_key["attachment_scanning"]["status"] == "not_connected"
    assert by_key["sender_domain_whois"]["status"] == "not_connected"
    assert by_key["malwarebazaar_hash"]["status"] == "not_connected"


def test_connected_analyzer_updates_capability_statuses():
    analyzer = FakeAnalyzer(
        file_analyzer=object(),
        ioc_investigator=FakeIOCInvestigator({"abusech": "test-key"}),
    )
    response = TestClient(_app(_user("admin"), analyzer)).get(
        "/api/analysis/email/capabilities"
    )
    by_key = {item["key"]: item for item in response.json()["capabilities"]}

    assert by_key["attachment_scanning"]["status"] == "active"
    assert by_key["sender_domain_whois"]["status"] == "active"
    assert by_key["malwarebazaar_hash"]["status"] == "active"


def test_connected_without_malwarebazaar_key_needs_config():
    analyzer = FakeAnalyzer(file_analyzer=object(), ioc_investigator=FakeIOCInvestigator())
    response = TestClient(_app(_user("admin"), analyzer)).get(
        "/api/analysis/email/capabilities"
    )
    by_key = {item["key"]: item for item in response.json()["capabilities"]}
    assert by_key["malwarebazaar_hash"]["status"] == "needs_config"


def test_non_admin_does_not_see_reasons():
    response = TestClient(_app(_user("SOC Analyst Tier 1-2"), FakeAnalyzer())).get(
        "/api/analysis/email/capabilities"
    )

    assert response.status_code == 200
    assert all("reason" not in item for item in response.json()["capabilities"])


def test_admin_sees_reasons():
    response = TestClient(_app(_user("admin"), FakeAnalyzer())).get(
        "/api/analysis/email/capabilities"
    )

    assert response.status_code == 200
    assert all("reason" in item for item in response.json()["capabilities"])


def test_unauthenticated_request_is_rejected():
    response = TestClient(_app()).get("/api/analysis/email/capabilities")
    assert response.status_code == 401


def test_cache_does_not_rebuild_for_same_analyzer():
    analyzer = FakeAnalyzer()
    client = TestClient(_app(_user("admin"), analyzer))
    first = client.get("/api/analysis/email/capabilities")
    second = client.get("/api/analysis/email/capabilities")

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()


def test_non_admin_cannot_refresh():
    response = TestClient(_app(_user("SOC Analyst Tier 1-2"), FakeAnalyzer())).get(
        "/api/analysis/email/capabilities?refresh=1"
    )
    assert response.status_code == 403
