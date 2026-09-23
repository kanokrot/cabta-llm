from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.app import _register_page_routes
from src.web.security import safe_relative_path


def _page_app() -> FastAPI:
    app = FastAPI()
    _register_page_routes(app)
    return app


def test_protected_pages_redirect_to_login_with_safe_next() -> None:
    with TestClient(_page_app()) as client:
        response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Fdashboard"


def test_login_and_register_pages_are_public_and_reject_open_redirects() -> None:
    with TestClient(_page_app()) as client:
        login = client.get("/login?next=https://evil.example", follow_redirects=False)
        register = client.get(
            "/accept-invite?token=invite-token",
            follow_redirects=False,
        )

    assert login.status_code == 200
    assert 'data-next="/"' in login.text
    assert register.status_code == 200
    assert "invite-token" in register.text


def test_safe_relative_path_rejects_external_and_ambiguous_targets() -> None:
    assert safe_relative_path("/dashboard?tab=stats") == "/dashboard?tab=stats"
    assert safe_relative_path("https://evil.example") == "/"
    assert safe_relative_path("//evil.example") == "/"
    assert safe_relative_path(r"/\\evil.example") == "/"
