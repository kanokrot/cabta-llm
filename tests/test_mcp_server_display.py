"""Display metadata and page statistics for MCP servers."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.web.app import _register_page_routes
from src.web.auth import get_current_user
from src.web.routes.mcp_management import router


def _user(role="admin"):
    return {
        "id": 1,
        "email": "mcp-display@example.test",
        "username": "mcp-display",
        "role": role,
        "is_active": 1,
    }


def _app():
    app = FastAPI()
    app.state.agent_store = SimpleNamespace(list_mcp_connections=lambda: [])
    app.state.config = {
        "mcp_servers": [
            {
                "name": "custom_server",
                "display_name": "Custom Label",
                "icon": "bi-stars",
                "category": "recon",
                "status": "connected",
            },
            {"name": "free_osint_tools", "status": "disconnected"},
            {"name": "unmapped_server", "status": "error: failed"},
        ]
    }
    app.state.mcp_client = SimpleNamespace(
        get_connection_status=lambda: {
            "custom_server": {"connected": True, "tool_count": 3},
            "free_osint_tools": {"connected": False, "tool_count": 2},
            "unmapped_server": {"connected": False, "tool_count": 4},
        }
    )
    app.dependency_overrides[get_current_user] = _user
    app.include_router(router, prefix="/api/mcp")
    _register_page_routes(app)
    return app


@pytest.mark.asyncio
async def test_display_fields_and_totals_match_between_api_and_page():
    app = _app()
    with TestClient(app) as client:
        api_response = client.get("/api/mcp/servers")
    assert api_response.status_code == 200
    api_servers = {server["name"]: server for server in api_response.json()["servers"]}

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
    page_response = await page_route.endpoint(request, _user())
    page_servers = {server["name"]: server for server in page_response.context["servers"]}

    expected = {
        "custom_server": ("Custom Label", "bi-stars"),
        "free_osint_tools": ("Free Osint", "bi-binoculars"),
        "unmapped_server": ("Unmapped Server", "bi-server"),
    }
    for name, fields in expected.items():
        assert (api_servers[name]["display_name"], api_servers[name]["icon"]) == fields
        assert (page_servers[name]["display_name"], page_servers[name]["icon"]) == fields

    assert page_response.context["tools_total"] == 9
    assert page_response.context["connected_count"] == 1
    assert page_response.context["attention_count"] == 2


def test_non_admin_server_payload_includes_display_fields():
    app = _app()
    app.dependency_overrides[get_current_user] = lambda: _user("Incident Responder")

    with TestClient(app) as client:
        response = client.get("/api/mcp/servers")

    assert response.status_code == 200
    servers = {server["name"]: server for server in response.json()["servers"]}
    assert servers["free_osint_tools"]["display_name"] == "Free Osint"
    assert servers["free_osint_tools"]["icon"] == "bi-binoculars"
