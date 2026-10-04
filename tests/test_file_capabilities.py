from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.file_capabilities import clear_file_capability_cache
from src.web.routes import analysis as analysis_routes


class FakeStringExtractor:
    extract_strings = staticmethod(lambda *_args, **_kwargs: {})
    extract_iocs_from_strings = staticmethod(lambda *_args, **_kwargs: {})


class FakeThreatIntel:
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}

    async def check_malwarebazaar(self, _hash):
        return {}


class FakeAnalyzer:
    def __init__(self, api_keys=None):
        self.string_extractor = FakeStringExtractor()
        self.threat_intel = FakeThreatIntel(api_keys)

    async def analyze(self, *_args, **_kwargs):
        return {}

    def _generate_mitre_mapping(self, *_args, **_kwargs):
        return []


def _user(role):
    return {
        "id": 1,
        "email": "file-capability@example.test",
        "username": "file-capability-user",
        "role": role,
        "is_active": 1,
    }


def _app(user=None, analyzer=None):
    app = FastAPI()
    app.state.malware_analyzer = analyzer
    app.state.analysis_manager = SimpleNamespace(get_job=lambda *_args, **_kwargs: None)
    app.include_router(analysis_routes.router, prefix="/api/analysis")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def setup_function():
    clear_file_capability_cache()


def test_returns_all_capabilities_with_groups_and_optional_fields():
    response = TestClient(_app(_user("admin"), FakeAnalyzer())).get(
        "/api/analysis/file/capabilities"
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["capabilities"]) == 10
    by_key = {item["key"]: item for item in payload["capabilities"]}
    assert {item["group"] for item in by_key.values()} == {
        "core", "detection", "format", "threat_intelligence"
    }
    assert by_key["macro_analysis"]["provider"] == "OLEVBA"
    assert by_key["pe_analysis"]["provider"] == "PEFILE"
    assert by_key["hash_reputation"]["provider"] == "MALWAREBAZAAR"
    assert by_key["malpedia_family"]["beta"] is True


def test_non_admin_does_not_see_reasons_and_admin_does():
    non_admin = TestClient(_app(_user("SOC Analyst Tier 1-2"), FakeAnalyzer())).get(
        "/api/analysis/file/capabilities"
    )
    assert non_admin.status_code == 200
    assert all("reason" not in item for item in non_admin.json()["capabilities"])

    clear_file_capability_cache()
    admin = TestClient(_app(_user("admin"), FakeAnalyzer())).get(
        "/api/analysis/file/capabilities"
    )
    assert admin.status_code == 200
    assert all("reason" in item for item in admin.json()["capabilities"])


def test_no_analyzer_wire_does_not_make_core_engines_active():
    response = TestClient(_app(_user("admin"), None)).get(
        "/api/analysis/file/capabilities"
    )
    by_key = {item["key"]: item for item in response.json()["capabilities"]}
    assert by_key["static_analysis"]["status"] != "active"
    assert by_key["string_extraction"]["status"] != "active"


def test_optional_imports_unavailable_do_not_make_engines_active(monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "pefile", None)
    monkeypatch.setitem(__import__("sys").modules, "oletools", None)
    monkeypatch.setitem(__import__("sys").modules, "oletools.olevba", None)
    monkeypatch.setitem(__import__("sys").modules, "yara", None)
    clear_file_capability_cache()

    response = TestClient(_app(_user("admin"), FakeAnalyzer())).get(
        "/api/analysis/file/capabilities?refresh=1"
    )
    by_key = {item["key"]: item for item in response.json()["capabilities"]}
    assert by_key["pe_analysis"]["status"] != "active"
    assert by_key["macro_analysis"]["status"] == "needs_config"
    assert by_key["macro_analysis"]["reason"] == "oletools is not installed"
    assert by_key["pe_analysis"]["status"] == "needs_config"
    assert by_key["pe_analysis"]["reason"] == "pefile is not installed"
    assert by_key["yara_rules"]["status"] == "needs_config"
    assert by_key["yara_rules"]["reason"] == "yara is not installed"


def test_unauthenticated_request_is_rejected():
    response = TestClient(_app()).get("/api/analysis/file/capabilities")
    assert response.status_code == 401


def test_capabilities_route_is_registered_before_analysis_id_route():
    client = TestClient(_app(_user("admin"), FakeAnalyzer()))
    capabilities = client.get("/api/analysis/file/capabilities")
    assert capabilities.status_code == 200

    analysis_id = client.get("/api/analysis/not-an-analysis")
    assert analysis_id.status_code == 404


def test_non_admin_cannot_refresh():
    response = TestClient(_app(_user("SOC Analyst Tier 1-2"), FakeAnalyzer())).get(
        "/api/analysis/file/capabilities?refresh=1"
    )
    assert response.status_code == 403
