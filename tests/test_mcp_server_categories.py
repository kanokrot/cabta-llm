"""MCP server categories stay consistent between the API and page."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.agent.mcp_tool_classification import SERVER_CATEGORIES
from src.web.app import _register_page_routes
from src.web.auth import get_current_user
from src.web.routes.mcp_management import CATEGORY_META, router


def _admin_user():
    return {
        "id": 1,
        "email": "admin@example.test",
        "username": "admin",
        "role": "admin",
        "is_active": 1,
    }


@pytest.mark.asyncio
async def test_server_categories_match_between_api_and_page():
    app = FastAPI()
    app.state.agent_store = SimpleNamespace(list_mcp_connections=lambda: [])
    app.state.config = {
        "mcp_servers": [
            {"name": "custom_intel", "category": "intel"},
            {"name": "osint_tools"},
            {"name": "unmapped_server"},
        ]
    }
    app.state.mcp_client = None
    app.dependency_overrides[get_current_user] = _admin_user
    app.include_router(router, prefix="/api/mcp")
    _register_page_routes(app)

    with TestClient(app) as client:
        api_response = client.get("/api/mcp/servers")
    assert api_response.status_code == 200
    api_categories = {
        server["name"]: server["category"]
        for server in api_response.json()["servers"]
    }

    page_route = next(route for route in app.routes if getattr(route, "path", None) == "/mcp/servers")
    request = Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/mcp/servers",
        "raw_path": b"/mcp/servers",
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "app": app,
    })
    page_response = await page_route.endpoint(request, _admin_user())
    page_categories = {
        server["name"]: server["category"]
        for server in page_response.context["servers"]
    }

    assert api_categories == page_categories == {
        "custom_intel": "intel",
        "osint_tools": "recon",
        "unmapped_server": "other",
    }
    assert {"recon", "malware", "forensics", "intel", "vuln", "other"} <= set(CATEGORY_META)
    assert SERVER_CATEGORIES == {
        "osint_tools": "recon",
        "free_osint_tools": "recon",
        "network_tools": "recon",
        "malwoverview_tools": "malware",
        "forensics_tools": "forensics",
        "remnux_tools": "malware",
        "threat_intel_tools": "intel",
        "remote_tools": "recon",
        "vulnerability-tools": "vuln",
    }
