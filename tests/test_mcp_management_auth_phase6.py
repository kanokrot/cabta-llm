"""Phase 6 MCP management authentication and fail-closed security tests."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.agent.agent_loop import AgentLoop
from src.agent.mcp_client import MCPClientManager, MCPConnection, MCPServerConfig
from src.agent.mcp_tool_classification import classify_mcp_tool
from src.agent.playbook_engine import PlaybookEngine
from src.agent.tool_registry import ToolRegistry
from src.web.auth import get_current_user
from src.web.routes.mcp_management import router


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _load_migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _auth_db(path: Path) -> None:
    _load_migration("001_create_users.py").migrate(str(path))
    _load_migration("002_add_username_and_admin_role.py").migrate(str(path))
    _load_migration("004_add_team_lead_role.py").migrate(str(path))
    with sqlite3.connect(path) as connection:
        connection.executemany(
            "INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)",
            [
                ("hunter@example.test", "hunter", "hash", "Threat Hunter"),
                ("admin@example.test", "admin", "hash", "admin"),
                ("responder@example.test", "responder", "hash", "Incident Responder"),
            ],
        )
        connection.commit()


def _user(role: str, user_id: int = 1) -> dict:
    return {
        "id": user_id,
        "email": f"{role.replace(' ', '-').lower()}@example.test",
        "username": role.replace(" ", "-").lower(),
        "role": role,
        "is_active": 1,
    }


class FakeMCP:
    def __init__(self):
        self.calls = []

    async def list_tools(self, server_name):
        return [
            {"name": "whois_lookup", "description": "safe", "inputSchema": {}},
            {"name": "unclassified_tool", "description": "external", "inputSchema": {}},
            {"name": "system_info_collect", "description": "remote", "inputSchema": {}},
        ]

    async def call_tool(self, server, tool, params):
        self.calls.append((server, tool, params))
        return {"ok": True}

    async def connect(self, config):
        return True

    async def disconnect(self, server_name):
        return None

    def get_connection_status(self):
        return {"osint_tools": {"connected": True, "tool_count": 3}}


def _app(monkeypatch, tmp_path, role: str | None = None):
    suffix = role.replace(" ", "_") if role else "anonymous"
    auth_db = tmp_path / f"auth_{suffix}.db"
    _auth_db(auth_db)
    monkeypatch.setenv("AUTH_DB_PATH", str(auth_db))

    app = FastAPI()
    if role is not None:
        app.dependency_overrides[get_current_user] = lambda: _user(role)
    app.state.agent_store = SimpleNamespace(
        list_mcp_connections=lambda: [
            {
                "id": "srv-1",
                "name": "osint_tools",
                "transport": "stdio",
                "config_json": json.dumps(
                    {
                        "name": "osint_tools",
                        "command": "python",
                        "args": ["-m", "src.mcp_servers.osint_tools"],
                        "env": {"SECRET": "do-not-return"},
                        "token": "token-do-not-return",
                    }
                ),
                "status": "connected",
                "created_at": "now",
            }
        ],
        save_mcp_connection=lambda name, transport, config: "new-id",
        delete_mcp_connection=lambda name: None,
    )
    app.state.config = {
        "mcp_servers": [
            {
                "name": "osint_tools",
                "transport": "stdio",
                "command": "python",
                "args": ["-m", "src.mcp_servers.osint_tools"],
                "env": {"SECRET": "do-not-return"},
                "token": "token-do-not-return",
            }
        ]
    }
    app.state.mcp_client = FakeMCP()
    app.state.tool_registry = ToolRegistry()
    app.include_router(router, prefix="/api/mcp")
    return app


def test_migration_009_is_fresh_idempotent_and_has_only_safe_audit_columns(tmp_path):
    db_path = tmp_path / "fresh.db"
    migration = _load_migration("009_add_mcp_audit.py")
    migration.migrate(str(db_path))
    migration.migrate(str(db_path))

    with sqlite3.connect(db_path) as connection:
        columns = [row[1] for row in connection.execute(
            "PRAGMA table_info(mcp_management_audit)"
        )]
        assert columns == [
            "id", "actor_user_id", "actor_role", "action", "server_name",
            "status", "occurred_at",
        ]
        assert "token" not in columns
        assert "secret" not in columns
        assert "config" not in columns


def test_migration_009_works_on_existing_001_to_008_db(tmp_path):
    db_path = tmp_path / "current.db"
    _auth_db(db_path)
    for filename in ("007_add_gmail_oauth.py", "008_add_notification_dedup.py"):
        _load_migration(filename).migrate(str(db_path))
    _load_migration("009_add_mcp_audit.py").migrate(str(db_path))

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO mcp_management_audit "
            "(actor_user_id, actor_role, action, server_name, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (1, "Threat Hunter", "check", "osint_tools", "success"),
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM mcp_management_audit"
        ).fetchone()[0] == 1


def test_categories_require_authentication(monkeypatch, tmp_path):
    app = _app(monkeypatch, tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/mcp/categories").status_code == 401


@pytest.mark.parametrize("method,path,payload", [
    ("get", "/api/mcp/servers", None),
    ("get", "/api/mcp/servers/osint_tools/tools", None),
    ("post", "/api/mcp/servers", {"name": "x", "transport": "stdio"}),
    ("delete", "/api/mcp/servers/osint_tools", None),
    ("post", "/api/mcp/servers/osint_tools/connect", None),
    ("post", "/api/mcp/servers/osint_tools/disconnect", None),
    ("post", "/api/mcp/servers/osint_tools/check", None),
])
def test_all_mcp_endpoints_require_authentication(monkeypatch, tmp_path, method, path, payload):
    app = _app(monkeypatch, tmp_path)
    with TestClient(app) as client:
        response = getattr(client, method)(path, json=payload) if payload else getattr(client, method)(path)
    assert response.status_code == 401


@pytest.mark.parametrize("role", [
    "SOC Analyst Tier 1-2", "Incident Responder", "Threat Hunter",
])
@pytest.mark.parametrize("method,path,payload", [
    ("post", "/api/mcp/servers", {"name": "x", "transport": "stdio"}),
    ("delete", "/api/mcp/servers/osint_tools", None),
    ("post", "/api/mcp/servers/osint_tools/connect", None),
    ("post", "/api/mcp/servers/osint_tools/disconnect", None),
    ("post", "/api/mcp/servers/osint_tools/check", None),
])
def test_non_admin_mcp_mutations_are_forbidden(monkeypatch, tmp_path, role, method, path, payload):
    app = _app(monkeypatch, tmp_path, role)
    with TestClient(app) as client:
        response = getattr(client, method)(path, json=payload) if payload else getattr(client, method)(path)
    assert response.status_code == 403


def test_server_listing_redacts_non_admin_and_admin_secrets(monkeypatch, tmp_path):
    for role in ("Incident Responder", "admin"):
        app = _app(monkeypatch, tmp_path, role)
        with TestClient(app) as client:
            response = client.get("/api/mcp/servers")
        assert response.status_code == 200
        raw = json.dumps(response.json())
        assert "token-do-not-return" not in raw
        assert "do-not-return" not in raw
        assert "config_json" not in raw
        if role == "admin":
            assert "command" in response.json()["servers"][0]
        else:
            assert set(response.json()["servers"][0]) <= {"name", "category", "status", "tool_count"}


def test_tools_endpoint_reuses_visibility_policy_and_fails_closed(monkeypatch, tmp_path):
    app = _app(monkeypatch, tmp_path, "Threat Hunter")
    with TestClient(app) as client:
        response = client.get("/api/mcp/servers/osint_tools/tools")
    assert response.status_code == 200
    names = {item["name"] for item in response.json()["tools"]}
    assert "osint_tools.whois_lookup" in names
    assert "osint_tools.unclassified_tool" not in names
    assert "osint_tools.system_info_collect" not in names

    app = _app(monkeypatch, tmp_path, "Incident Responder")
    with TestClient(app) as client:
        assert client.get("/api/mcp/servers/osint_tools/tools").status_code == 403


def test_admin_mutations_write_minimal_audit_records(monkeypatch, tmp_path):
    app = _app(monkeypatch, tmp_path, "admin")
    with TestClient(app) as client:
        assert client.post(
            "/api/mcp/servers",
            json={"name": "added", "transport": "stdio", "token": "secret"},
        ).status_code == 200
        assert client.delete("/api/mcp/servers/osint_tools").status_code == 200
        assert client.post("/api/mcp/servers/osint_tools/connect").status_code == 200
        assert client.post("/api/mcp/servers/osint_tools/disconnect").status_code == 200
        assert client.post("/api/mcp/servers/osint_tools/check").status_code == 200

    with sqlite3.connect(app.state._auth_db_path if hasattr(app.state, "_auth_db_path") else str(tmp_path / "auth_admin.db")) as connection:
        rows = connection.execute(
            "SELECT actor_user_id, actor_role, action, server_name, status "
            "FROM mcp_management_audit ORDER BY id"
        ).fetchall()
    assert [row[2] for row in rows] == [
        "add_server", "delete_server", "connect", "disconnect", "check",
    ]
    assert all(row[0] == 1 and row[1] == "admin" for row in rows)
    assert all("secret" not in json.dumps(row) for row in rows)


def test_mcp_servers_html_page_is_admin_only(monkeypatch, tmp_path):
    from fastapi.templating import Jinja2Templates
    from src.web.app import _register_page_routes

    app = _app(monkeypatch, tmp_path, "Incident Responder")
    app.state.templates = Jinja2Templates(directory=str(ROOT / "templates"))
    from src.web.app import _register_page_routes as register_pages
    register_pages(app)
    with TestClient(app) as client:
        response = client.get("/mcp/servers")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_run_tool_blocks_unclassified_mcp_fallback_for_threat_hunter():
    mcp = FakeMCP()
    loop = AgentLoop(config={}, tool_registry=ToolRegistry(), agent_store=SimpleNamespace(), mcp_client=mcp)
    result = await loop.run_tool(
        "mcp:osint_tools/unclassified_tool", {}, role="Threat Hunter",
    )
    assert "not allowed" in result["error"].lower()
    assert mcp.calls == []


@pytest.mark.asyncio
async def test_discovery_replaces_external_classification_and_unknown_is_dangerous():
    class Client:
        async def list_tools(self):
            return SimpleNamespace(tools=[
                SimpleNamespace(
                    name="whois_lookup",
                    description="safe",
                    inputSchema={},
                    category="sandbox",
                    is_dangerous=True,
                ),
                {"name": "new_tool", "category": "analysis", "is_dangerous": False},
            ])

    manager = MCPClientManager()
    connection = MCPConnection(
        config=MCPServerConfig(name="osint_tools", transport="stdio"),
        client=Client(),
    )
    tools = await manager._discover_tools(connection)
    assert tools[0]["category"] == "osint"
    assert tools[0]["is_dangerous"] is False
    assert tools[1]["is_dangerous"] is True
    assert classify_mcp_tool("unknown_server", "unknown_tool")["is_dangerous"] is True


@pytest.mark.asyncio
async def test_playbook_dispatcher_passes_role_to_agent_loop():
    calls = []

    async def run_tool(tool_name, params, **kwargs):
        calls.append(kwargs)
        return {"ok": True}

    engine = PlaybookEngine(
        SimpleNamespace(run_tool=run_tool), SimpleNamespace(),
    )
    result = await engine._run_tool(
        "mcp:osint_tools/whois_lookup", {}, 5, role="Threat Hunter",
    )
    assert result == {"ok": True}
    assert calls[0]["role"] == "Threat Hunter"
