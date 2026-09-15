"""Phase 2 RBAC coverage for REST routes and WebSocket authentication."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.web.auth import get_current_user, require_role
from src.web.routes import agent as agent_routes
from src.web.routes import chat as chat_routes
from src.web.routes import dashboard as dashboard_routes
from src.web.routes import reports as reports_routes
from src.web.routes import playbooks as playbooks_routes
from src.web import websocket as websocket_routes


SOC_ANALYST = "SOC Analyst Tier 1-2"
INCIDENT_RESPONDER = "Incident Responder"
THREAT_HUNTER = "Threat Hunter"
ADMIN = "admin"
ALL_ROLES = (SOC_ANALYST, INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN)


def _user(role: str) -> dict:
    return {
        "id": 100 + ALL_ROLES.index(role),
        "email": f"{role.lower().replace(' ', '.')}@example.test",
        "username": role.lower().replace(" ", "-"),
        "role": role,
        "is_active": 1,
    }


def _with_user(app: FastAPI, role: str) -> FastAPI:
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    return app


def _agent_app(role: str) -> FastAPI:
    app = _with_user(FastAPI(), role)
    owner_id = _user(role)["id"]
    app.state.agent_loop = SimpleNamespace(
        investigate=AsyncMock(return_value="session-1"),
        approve_action=AsyncMock(return_value=True),
        reject_action=AsyncMock(return_value=True),
        cancel_session=AsyncMock(),
        get_state=lambda _session_id: None,
    )
    app.state.agent_store = SimpleNamespace(
        get_agent_stats=lambda: {"total": 1},
        get_session=lambda session_id, user_id=None: (
            {
                "id": session_id,
                "status": "completed",
                "findings": [],
                "metadata": {},
                "goal": "test goal",
                "user_id": owner_id,
            }
            if user_id is None or user_id == owner_id
            else None
        ),
        get_steps=lambda _session_id: [],
        list_sessions=lambda **_kwargs: [{"id": "session-1", "user_id": owner_id}],
        delete_session=lambda _session_id: True,
        get_audit_log=lambda **_kwargs: [],
    )
    app.state.tool_registry = SimpleNamespace(
        list_tools=lambda category=None: [
            SimpleNamespace(to_dict=lambda: {"name": "test-tool"})
        ]
    )
    app.state.mcp_client = None
    app.state.investigation_memory = SimpleNamespace(
        recall_ioc=lambda _ioc: None,
        get_pattern_summary=lambda: {"patterns": []},
    )
    app.state.sandbox_orchestrator = SimpleNamespace(
        get_sandbox_status=lambda: {"available": True}
    )
    app.state.correlation_engine = SimpleNamespace(
        correlate=lambda _findings: {"clusters": []}
    )
    app.include_router(agent_routes.router, prefix="/api/agent")
    return app


AGENT_CASES = (
    ("post", "/api/agent/investigate", {"goal": "investigate test"}),
    ("get", "/api/agent/stats", None),
    ("get", "/api/agent/tools", None),
    ("get", "/api/agent/memory/ioc/example.test", None),
    ("get", "/api/agent/memory/stats", None),
    ("get", "/api/agent/sandbox/status", None),
    ("get", "/api/agent/correlation/session-1", None),
    ("get", "/api/agent/sessions", None),
    ("get", "/api/agent/sessions/session-1", None),
    ("post", "/api/agent/sessions/session-1/approve", {"approved": True}),
    ("post", "/api/agent/sessions/session-1/cancel", None),
    ("delete", "/api/agent/sessions/session-1", None),
    ("get", "/api/agent/sessions/session-1/audit", None),
)


@pytest.mark.parametrize("method,path,payload", AGENT_CASES)
@pytest.mark.parametrize("role", ALL_ROLES)
def test_agent_routes_require_threat_hunter_or_admin(method, path, payload, role):
    app = _agent_app(role)
    with TestClient(app) as client:
        response = getattr(client, method)(path, json=payload) if payload else getattr(client, method)(path)

    expected_status = 200 if role in {THREAT_HUNTER, ADMIN} else 403
    assert response.status_code == expected_status


def _playbooks_app(role: str, monkeypatch) -> FastAPI:
    class FakeReportGenerator:
        def generate_ioc_report(self, _result, _ioc, output_path):
            Path(output_path).write_text("<html>report</html>", encoding="utf-8")
            return output_path

    monkeypatch.setattr(playbooks_routes, "HTMLReportGenerator", FakeReportGenerator)
    app = _with_user(FastAPI(), role)
    owner_id = _user(role)["id"]
    app.state.playbook_engine = SimpleNamespace(
        list_playbooks=lambda: [{"id": "playbook-1"}],
        get_playbook=lambda _playbook_id: {"id": "playbook-1"},
        start=AsyncMock(return_value="session-1"),
        execute_from_step=AsyncMock(return_value="session-1"),
    )
    app.state.agent_store = SimpleNamespace(
        get_session=lambda _session_id, user_id=None: (
            {
                "user_id": owner_id,
                "metadata": {
                    "ioc_investigation_result": {"verdict": "CLEAN"},
                    "ioc": "example.test",
                },
            }
            if user_id is None or user_id == owner_id
            else None
        )
    )
    app.include_router(playbooks_routes.router, prefix="/api/playbooks")
    return app


PLAYBOOK_CASES = (
    ("get", "/api/playbooks", None),
    ("get", "/api/playbooks/playbook-1", None),
    ("post", "/api/playbooks/playbook-1/run", {"params": {}}),
    ("post", "/api/playbooks/sessions/session-1/approve", {"approved": True}),
    ("get", "/api/playbooks/sessions/session-1/report", None),
)


@pytest.mark.parametrize("method,path,payload", PLAYBOOK_CASES)
@pytest.mark.parametrize("role", ALL_ROLES)
def test_playbook_routes_require_incident_responder_or_admin(
    method, path, payload, role, monkeypatch
):
    app = _playbooks_app(role, monkeypatch)
    with TestClient(app) as client:
        response = getattr(client, method)(path, json=payload) if payload else getattr(client, method)(path)

    expected_status = 200 if role in {INCIDENT_RESPONDER, ADMIN} else 403
    assert response.status_code == expected_status


def _chat_app(role: str) -> FastAPI:
    app = _with_user(FastAPI(), role)
    owner_id = _user(role)["id"]
    app.state.agent_loop = SimpleNamespace(
        investigate=AsyncMock(return_value="session-1"),
        get_state=lambda _session_id: None,
    )
    app.state.playbook_engine = SimpleNamespace(start=AsyncMock(return_value="session-1"))
    app.state.agent_store = SimpleNamespace(
        get_session=lambda session_id, user_id=None: (
            {
                "id": session_id,
                "status": "completed",
                "goal": "test goal",
                "user_id": owner_id,
            }
            if user_id is None or user_id == owner_id
            else None
        ),
        get_steps=lambda _session_id: [],
        list_sessions=lambda **_kwargs: [{"id": "session-1", "user_id": owner_id}],
    )
    app.include_router(chat_routes.router, prefix="/api/chat")
    return app


@pytest.mark.parametrize("role", ALL_ROLES)
@pytest.mark.parametrize(
    "payload,allowed_roles",
    (
        (
            {"message": "run playbook", "playbook_id": "playbook-1"},
            {INCIDENT_RESPONDER, ADMIN},
        ),
        ({"message": "investigate domain"}, {THREAT_HUNTER, ADMIN}),
    ),
)
def test_chat_post_is_branch_aware(role, payload, allowed_roles):
    with TestClient(_chat_app(role)) as client:
        response = client.post("/api/chat", json=payload)

    expected_status = 200 if role in allowed_roles else 403
    assert response.status_code == expected_status


@pytest.mark.parametrize("role", ALL_ROLES)
@pytest.mark.parametrize("path", ("/api/chat/sessions", "/api/chat/sessions/session-1"))
def test_chat_session_reads_are_admin_only_until_phase_25(role, path):
    with TestClient(_chat_app(role)) as client:
        response = client.get(path)

    expected_status = 200
    assert response.status_code == expected_status


def test_require_role_remains_backward_compatible_with_admin_string():
    app = _with_user(FastAPI(), ADMIN)

    @app.get("/admin")
    def admin_only(_user: dict = Depends(require_role("admin"))):
        return {"ok": True}

    with TestClient(app) as client:
        response = client.get("/admin")

    assert response.status_code == 200


def test_require_role_accepts_allowed_role_list():
    app = _with_user(FastAPI(), THREAT_HUNTER)

    @app.get("/investigate")
    def investigate(
        _user: dict = Depends(require_role([THREAT_HUNTER, ADMIN])),
    ):
        return {"ok": True}

    with TestClient(app) as client:
        response = client.get("/investigate")

    assert response.status_code == 200


@pytest.mark.parametrize("roles", ([], ["not-a-role"]))
def test_require_role_rejects_empty_or_unknown_roles(roles):
    with pytest.raises(ValueError, match="Unsupported role"):
        require_role(roles)


def _websocket_app(agent_user_id=_user(THREAT_HUNTER)["id"]) -> FastAPI:
    app = FastAPI()
    app.state.analysis_manager = SimpleNamespace(
        subscribe=lambda _analysis_id: asyncio.Queue(),
        unsubscribe=lambda _analysis_id, _queue: None,
        get_job=lambda _analysis_id: {"status": "completed", "progress": 100},
    )
    app.state.agent_store = SimpleNamespace(
        get_session=lambda session_id, user_id=None: {
            "id": session_id,
            "status": "completed",
            "user_id": agent_user_id,
        },
        get_steps=lambda _session_id: [],
    )
    app.state.agent_loop = None
    app.include_router(websocket_routes.router)
    return app


def _patch_websocket_user(monkeypatch, role: str) -> None:
    monkeypatch.setattr(
        websocket_routes,
        "get_current_user",
        lambda token: _user(role) if token == "valid-token" else (_ for _ in ()).throw(
            HTTPException(status_code=401)
        ),
    )


def _assert_websocket_closed(client, path: str, first_message: dict | None) -> int:
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(path) as websocket:
            if first_message is not None:
                websocket.send_json(first_message)
            websocket.receive_json()
    return exc_info.value.code


@pytest.mark.parametrize(
    "path,allowed_roles",
    (
        ("/ws/analysis/analysis-1", set(ALL_ROLES)),
        ("/ws/agent/session-1", {THREAT_HUNTER, ADMIN}),
    ),
)
@pytest.mark.parametrize("role", ALL_ROLES)
def test_websocket_roles_allow_only_the_expected_role_and_admin(
    path, allowed_roles, role, monkeypatch
):
    _patch_websocket_user(monkeypatch, role)
    with TestClient(_websocket_app()) as client:
        if role not in allowed_roles:
            assert _assert_websocket_closed(
                client, path, {"type": "auth", "token": "valid-token"}
            ) == 1008
            return

        with client.websocket_connect(path) as websocket:
            websocket.send_json({"type": "auth", "token": "valid-token"})
            assert websocket.receive_json()["type"] in {"status", "session_state"}


@pytest.mark.parametrize("path", ("/ws/analysis/analysis-1", "/ws/agent/session-1"))
def test_websocket_rejects_missing_or_invalid_first_auth_message(path, monkeypatch):
    _patch_websocket_user(monkeypatch, THREAT_HUNTER)
    with TestClient(_websocket_app()) as client:
        assert _assert_websocket_closed(client, path, {"type": "not-auth"}) == 1008


@pytest.mark.parametrize("path", ("/ws/analysis/analysis-1", "/ws/agent/session-1"))
def test_websocket_rejects_invalid_token(path, monkeypatch):
    _patch_websocket_user(monkeypatch, THREAT_HUNTER)
    with TestClient(_websocket_app()) as client:
        assert _assert_websocket_closed(
            client, path, {"type": "auth", "token": "invalid-token"}
        ) == 1008


def test_websocket_rejects_first_message_timeout_with_1008(monkeypatch):
    _patch_websocket_user(monkeypatch, THREAT_HUNTER)

    async def timeout(awaitable, timeout):
        awaitable.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(websocket_routes.asyncio, "wait_for", timeout)
    with TestClient(_websocket_app()) as client:
        assert _assert_websocket_closed(client, "/ws/agent/session-1", None) == 1008


def test_agent_websocket_rejects_wrong_owner_with_1008(monkeypatch):
    owner_id = _user(THREAT_HUNTER)["id"]
    monkeypatch.setattr(
        websocket_routes,
        "get_current_user",
        lambda _token: {**_user(THREAT_HUNTER), "id": owner_id + 1000},
    )
    with TestClient(_websocket_app(agent_user_id=owner_id)) as client:
        assert _assert_websocket_closed(
            client,
            "/ws/agent/session-1",
            {"type": "auth", "token": "valid-token"},
        ) == 1008


def test_agent_websocket_rejects_legacy_null_owner_for_non_admin_with_1008(monkeypatch):
    _patch_websocket_user(monkeypatch, THREAT_HUNTER)
    with TestClient(_websocket_app(agent_user_id=None)) as client:
        assert _assert_websocket_closed(
            client,
            "/ws/agent/session-1",
            {"type": "auth", "token": "valid-token"},
        ) == 1008


def test_agent_websocket_allows_legacy_null_owner_for_admin(monkeypatch):
    _patch_websocket_user(monkeypatch, ADMIN)
    with TestClient(_websocket_app(agent_user_id=None)) as client:
        with client.websocket_connect("/ws/agent/session-1") as websocket:
            websocket.send_json({"type": "auth", "token": "valid-token"})
            assert websocket.receive_json()["type"] == "session_state"


def _dashboard_app(role: str, calls: list) -> FastAPI:
    app = _with_user(FastAPI(), role)
    owner_id = _user(role)["id"]
    app.state.analysis_manager = SimpleNamespace(
        get_stats=lambda: {"total_analyses": 1},
        list_jobs=lambda **kwargs: calls.append(kwargs) or [{"id": "job-1"}],
    )
    app.include_router(dashboard_routes.router, prefix="/api/dashboard")
    return app


@pytest.mark.parametrize("role", ALL_ROLES)
def test_dashboard_stats_and_sources_require_login_for_all_roles(role):
    calls = []
    with TestClient(_dashboard_app(role, calls)) as client:
        assert client.get("/api/dashboard/stats").status_code == 200
        assert client.get("/api/dashboard/sources").status_code == 200


@pytest.mark.parametrize("role", ALL_ROLES)
def test_dashboard_recent_filters_non_admin_and_leaves_admin_unscoped(role):
    calls = []
    with TestClient(_dashboard_app(role, calls)) as client:
        response = client.get("/api/dashboard/recent")

    assert response.status_code == 200
    assert calls == [
        {
            "limit": 10,
            "user_id": None if role == ADMIN else _user(role)["id"],
        }
    ]


def _reports_app(role: str, monkeypatch) -> FastAPI:
    app = _with_user(FastAPI(), role)
    app.state.analysis_manager = SimpleNamespace(
        get_job=lambda _analysis_id: {
            "id": "analysis-1",
            "result": {"detection_rules": {"kql": "DeviceProcessEvents"}},
        },
        update_detection_rule=lambda *_args: True,
    )
    app.state.templates = SimpleNamespace(
        TemplateResponse=lambda *args, **kwargs: {"ok": True}
    )
    monkeypatch.setattr(
        reports_routes,
        "validate_rule",
        lambda *_args: {"valid": True},
    )
    app.include_router(reports_routes.router, prefix="/api/reports")
    return app


@pytest.mark.parametrize("role", ALL_ROLES)
def test_reports_read_is_shared_across_authenticated_roles(role, monkeypatch):
    with TestClient(_reports_app(role, monkeypatch)) as client:
        response = client.get("/api/reports/analysis-1/json")

    assert response.status_code == 200


REPORT_MUTATION_CASES = (
    ("put", "/api/reports/analysis-1/rules/kql", THREAT_HUNTER, 200),
    ("put", "/api/reports/analysis-1/rules/kql", ADMIN, 200),
    ("put", "/api/reports/analysis-1/rules/kql", SOC_ANALYST, 403),
    ("put", "/api/reports/analysis-1/rules/kql", INCIDENT_RESPONDER, 403),
    ("post", "/api/reports/analysis-1/rules/kql/approve", INCIDENT_RESPONDER, 200),
    ("post", "/api/reports/analysis-1/rules/kql/approve", ADMIN, 200),
    ("post", "/api/reports/analysis-1/rules/kql/approve", SOC_ANALYST, 403),
    ("post", "/api/reports/analysis-1/rules/kql/approve", THREAT_HUNTER, 403),
    ("post", "/api/reports/analysis-1/rules/kql/mark-deployed", INCIDENT_RESPONDER, 200),
    ("post", "/api/reports/analysis-1/rules/kql/mark-deployed", ADMIN, 200),
    ("post", "/api/reports/analysis-1/rules/kql/mark-deployed", SOC_ANALYST, 403),
    ("post", "/api/reports/analysis-1/rules/kql/mark-deployed", THREAT_HUNTER, 403),
)


@pytest.mark.parametrize("method,path,role,expected_status", REPORT_MUTATION_CASES)
def test_reports_rule_mutations_enforce_role_matrix(
    method, path, role, expected_status, monkeypatch
):
    with TestClient(_reports_app(role, monkeypatch)) as client:
        if path.endswith("/mark-deployed") and expected_status == 200:
            approval = client.post(
                "/api/reports/analysis-1/rules/kql/approve",
                json={},
            )
            assert approval.status_code == 200

        payload = {"content": "DeviceProcessEvents"} if method == "put" else {}
        response = getattr(client, method)(path, json=payload)

    assert response.status_code == expected_status
