from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from tests.test_page_auth_guard import _session_cookie_for_role


ROOT = Path(__file__).resolve().parents[1]


def _integrations_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    _register_page_routes(app)
    return app


def _client_for_role(monkeypatch, tmp_path: Path, role: str) -> TestClient:
    token = _session_cookie_for_role(monkeypatch, tmp_path, role)
    client = TestClient(_integrations_app())
    client.cookies.set("cabta_session", token)
    return client


def test_integrations_page_role_access(monkeypatch, tmp_path: Path) -> None:
    for index, (role, expected_status) in enumerate((
        ("Incident Responder", 200),
        ("admin", 200),
        ("SOC Analyst Tier 1-2", 403),
    )):
        role_tmp_path = tmp_path / str(index)
        role_tmp_path.mkdir()
        client = _client_for_role(monkeypatch, role_tmp_path, role)
        with client:
            response = client.get("/integrations", follow_redirects=False)

        assert response.status_code == expected_status
        if expected_status == 403:
            assert response.json() == {"detail": "Insufficient permissions"}


def test_integrations_page_shows_bundle_details_without_version_or_copy(
    monkeypatch, tmp_path: Path
) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    with client:
        response = client.get("/integrations")

    assert response.status_code == 200
    assert "Wazuh Alert Triage" in response.text
    assert 'href="/api/integrations/wazuh/download"' in response.text
    for sample in sorted((ROOT / "deploy" / "wazuh" / "samples").glob("*.json")):
        assert sample.name in response.text
    assert "Version" not in response.text
    assert re.search(
        r"<button\b(?=[^>]*\bdisabled\b)[^>]*>[\s\S]*?\bCopy\b",
        response.text,
        re.IGNORECASE,
    ) is None


def test_wazuh_download_contains_expected_bundle_files(monkeypatch, tmp_path: Path) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    with client:
        response = client.get("/api/integrations/wazuh/download")

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
        actual_names = set(bundle.namelist())

    bundle_prefix = "cabta-wazuh-integration/"
    bundle_root = ROOT / "deploy" / "wazuh"
    expected_names = {
        f"{bundle_prefix}{name}"
        for name in ("README.md", "custom-cabta", "ossec.conf")
    }
    expected_names.update(
        f"{bundle_prefix}samples/{sample.name}"
        for sample in sorted((bundle_root / "samples").glob("*.json"))
    )
    assert actual_names == expected_names
