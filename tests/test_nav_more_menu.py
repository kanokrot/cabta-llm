from __future__ import annotations

import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import page_auth
from src.web.analysis_manager import AnalysisManager
from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware


ROLES = [
    "SOC Analyst Tier 1-2",
    "Incident Responder",
    "Threat Hunter",
    "Team Lead",
    "admin",
]

HREFS = {
    "/agent/investigations": {"Threat Hunter", "admin"},
    "/agent/playbooks": {"Incident Responder", "admin"},
    "/analysis/ioc": {"SOC Analyst Tier 1-2", "admin"},
    "/history": set(ROLES),
    "/cases": set(ROLES),
    "/management": {"Team Lead", "admin"},
    "/tickets": set(ROLES),
    "/mcp/servers": {"admin"},
    "/settings": {"admin"},
    "/": {"Threat Hunter", "admin"},
}


def _build_page_app(tmp_path) -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    app.state.analysis_manager = AnalysisManager(db_path=str(tmp_path / "analysis.db"))
    _register_page_routes(app)
    return app


@pytest.mark.parametrize("role", ROLES)
def test_more_menu_role_gates_and_unique_nav_links(tmp_path, monkeypatch, role: str) -> None:
    user = {
        "id": 1,
        "email": "test@example.test",
        "username": "test-user",
        "role": role,
        "is_active": 1,
    }
    monkeypatch.setattr(page_auth, "get_current_user", lambda token, request=None: user)

    with TestClient(_build_page_app(tmp_path)) as client:
        client.cookies.set("cabta_session", "test-token")
        response = client.get("/dashboard")

    assert response.status_code == 200
    nav_start = response.text.index("<nav ")
    nav_end = response.text.index("</nav>", nav_start) + len("</nav>")
    nav_html = response.text[nav_start:nav_end]

    for href, roles in HREFS.items():
        nav_link_hrefs = []
        for anchor in re.findall(r'<a\b[^>]*>', nav_html):
            if re.search(r'class="[^"]*(?:nav-link|dropdown-item)[^"]*"', anchor):
                href_match = re.search(r'href="([^"]+)"', anchor)
                if href_match:
                    nav_link_hrefs.append(href_match.group(1))
        assert nav_link_hrefs.count(href) == (1 if role in roles else 0)

    assert len(re.findall(r">\s*More\s*</a>", nav_html)) == 1
    assert nav_html.count('<h6 class="dropdown-header">Agent</h6>') == (
        1 if role in {"Incident Responder", "Threat Hunter", "admin"} else 0
    )
    assert nav_html.count('<h6 class="dropdown-header">Management</h6>') == 1
    assert len(re.findall(r'<h6 class="dropdown-header">(?:<i[^>]*></i>)?System</h6>', nav_html)) == (
        1 if role == "admin" else 0
    )
