"""D10.4 negative boundary tests.

These tests intentionally come before the positive visibility cases.  They
lock in fail-closed behavior and protect the response boundary from raw
internal data before the policy is wired into every route.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web import websocket as websocket_routes
from src.web.auth import get_current_user
from src.web.routes import cases as cases_routes
from src.web.routes import playbooks as playbooks_routes
from src.web.visibility import VisibilityError


SOC = "SOC Analyst Tier 1-2"
INCIDENT_RESPONDER = "Incident Responder"
THREAT_HUNTER = "Threat Hunter"
TEAM_LEAD = "Team Lead"
ADMIN = "admin"


def _user(role: str, user_id: int = 100) -> dict:
    return {
        "id": user_id,
        "email": "user@example.test",
        "username": "user",
        "role": role,
        "is_active": 1,
    }


class _FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)


# ---------------------------------------------------------------------------
# Fail-closed policy and serializer tests (negative cases first)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["", "unknown", None])
def test_unknown_role_fails_closed(role) -> None:
    from src.web.visibility import authorize_flow

    with pytest.raises(VisibilityError):
        authorize_flow(role, "analysis")


def test_unknown_flow_fails_closed() -> None:
    from src.web.visibility import authorize_flow

    with pytest.raises(VisibilityError):
        authorize_flow(ADMIN, "unknown-flow")


def test_unknown_websocket_frame_fails_closed_without_sending() -> None:
    socket = _FakeWebSocket()

    with pytest.raises(VisibilityError):
        # The helper must reject an unknown flow before touching the socket.
        import asyncio

        asyncio.run(
            websocket_routes._send_visible(
                socket,
                {"type": "future_frame", "secret": "must-not-leak"},
                role=ADMIN,
                flow="unknown-flow",
            )
        )

    assert socket.sent == []


@pytest.mark.parametrize("flow", ["analysis", "report", "dashboard"])
def test_analysis_like_serializers_never_return_raw_internal_fields(flow) -> None:
    from src.web.visibility import serialize_response

    payload = {
        "id": "job-1",
        "analysis_type": "file",
        "params": {
            "filename": "sample.exe",
            "temp_path": "C:/private/sample.exe",
            "credential": "secret",
        },
        "result": {
            "summary": "safe summary",
            "provider_payload": {"api_key": "secret"},
            "raw_source": "secret-provider-data",
        },
        "temp_path": "C:/private/sample.exe",
        "credentials": {"token": "secret"},
    }

    serialized = serialize_response(payload, role=ADMIN, flow=flow)
    serialized_text = str(serialized)
    for forbidden in (
        "params",
        "provider_payload",
        "raw_source",
        "temp_path",
        "credentials",
        "api_key",
        "secret-provider-data",
    ):
        assert forbidden not in serialized_text


def test_agent_websocket_frame_does_not_expose_params_result_or_paths() -> None:
    socket = _FakeWebSocket()
    frame = {
        "type": "tool_result",
        "tool": "threat_intel.lookup",
        "params": {"ioc": "8.8.8.8", "token": "secret"},
        "result": {"provider_payload": "secret", "file_path": "/tmp/x"},
        "result_preview": "secret-provider-data",
    }

    import asyncio

    asyncio.run(
        websocket_routes._send_visible(
            socket,
            frame,
            role=THREAT_HUNTER,
            flow="agent",
        )
    )

    assert socket.sent
    sent_text = str(socket.sent[0])
    assert "params" not in sent_text
    assert "'result':" not in sent_text
    assert "secret" not in sent_text
    assert "/tmp/x" not in sent_text


# ---------------------------------------------------------------------------
# Direct route boundary tests
# ---------------------------------------------------------------------------


def test_threat_hunter_is_denied_direct_playbook_route(monkeypatch) -> None:
    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: _user(THREAT_HUNTER)
    app.state.playbook_engine = SimpleNamespace(
        list_playbooks=lambda: [{"id": "pb-1"}],
        get_playbook=lambda _playbook_id: {"id": "pb-1"},
    )
    app.include_router(playbooks_routes.router, prefix="/api/playbooks")

    with TestClient(app) as client:
        assert client.get("/api/playbooks").status_code == 403
        assert client.get("/api/playbooks/pb-1").status_code == 403


def test_cases_require_authentication() -> None:
    app = FastAPI()
    app.include_router(cases_routes.router, prefix="/api/cases")

    with TestClient(app) as client:
        response = client.get("/api/cases")

    assert response.status_code == 401


def test_team_lead_cannot_mutate_case_status_or_notes(tmp_path) -> None:
    from src.web.case_store import CaseStore

    store = CaseStore(str(tmp_path / "cases.db"))
    case_id = store.create_case("D10.4 case")

    app = FastAPI()
    app.state.case_store = store
    app.dependency_overrides[get_current_user] = lambda: _user(TEAM_LEAD, 900)
    app.include_router(cases_routes.router, prefix="/api/cases")

    with TestClient(app) as client:
        status_response = client.patch(
            f"/api/cases/{case_id}/status",
            json={"status": "Resolved"},
        )
        note_response = client.post(
            f"/api/cases/{case_id}/notes",
            json={"content": "must be denied"},
        )

    assert status_response.status_code == 403
    assert note_response.status_code == 403


# ---------------------------------------------------------------------------
# Positive contract checks (kept after the negative boundary checks)
# ---------------------------------------------------------------------------


def test_admin_receives_detail_but_no_internal_analysis_fields() -> None:
    from src.web.visibility import serialize_report_payload

    payload = {
        "id": "job-2",
        "params": {"value": "evil.example", "temp_path": "C:/private/x"},
        "result": {
            "verdict": "MALICIOUS",
            "summary": "malicious domain",
            "findings": [{"type": "reputation", "summary": "flagged"}],
            "provider_payload": {"secret": "never"},
        },
    }

    visible = serialize_report_payload(payload, role=ADMIN)

    assert visible["verdict"] == "MALICIOUS"
    assert visible["findings"][0]["summary"] == "flagged"
    assert "provider_payload" not in visible


def test_threat_hunter_tool_allowlist_denies_dangerous_tool() -> None:
    from src.web.visibility import is_tool_allowed

    safe = {"name": "lookup", "category": "threat_intel", "is_dangerous": False}
    dangerous = {"name": "contain", "category": "edr", "is_dangerous": True}

    assert is_tool_allowed(THREAT_HUNTER, safe)
    assert not is_tool_allowed(THREAT_HUNTER, dangerous)
