from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.agent.agent_store import AgentStore
from src.web.auth import get_current_user
from src.web.routes import agent as agent_routes
from src.web.routes import chat as chat_routes


def _client(tmp_path, role="Threat Hunter"):
    store = AgentStore(str(tmp_path / "instant-reply.db"))
    async def classify(messages, tools=None):
        import json

        latest = json.loads(messages[-1]["content"])["latest_message"].lower()
        if latest == "asdfghjkl":
            intent = "clarify"
        elif latest in {"hello", "hello there", "help", "สวัสดี"}:
            intent = "converse"
        else:
            intent = "investigate"
        reply = "Please clarify your request." if intent == "clarify" else "Hello."
        return json.dumps({"intent": intent, "reply": reply})

    loop = SimpleNamespace(
        investigate=AsyncMock(return_value="spy-session"),
        _chat_with_tools=AsyncMock(side_effect=classify),
    )
    playbook_engine = SimpleNamespace(start=AsyncMock(return_value="playbook-session"))
    app = FastAPI()
    app.state.agent_loop = loop
    app.state.agent_store = store
    app.state.playbook_engine = playbook_engine
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 17,
        "email": "instant-test@example.test",
        "username": "instant-test",
        "role": role,
        "is_active": 1,
    }
    app.include_router(agent_routes.router, prefix="/api/agent")
    app.include_router(chat_routes.router, prefix="/api/chat")
    return app, store, loop, playbook_engine


@pytest.mark.parametrize(
    ("path", "body", "intent"),
    [
        ("/api/agent/investigate", {"goal": "hello"}, "converse"),
        ("/api/agent/investigate", {"goal": "hello there"}, "converse"),
        ("/api/agent/investigate", {"goal": "help"}, "converse"),
        ("/api/agent/investigate", {"goal": "สวัสดี"}, "converse"),
        ("/api/chat", {"message": "hello"}, "converse"),
        ("/api/chat", {"message": "help"}, "converse"),
        ("/api/chat", {"message": "สวัสดี"}, "converse"),
    ],
)
def test_common_intents_return_without_investigation(tmp_path, path, body, intent):
    app, store, loop, _ = _client(tmp_path)

    with TestClient(app) as client:
        response = client.post(path, json=body)

    assert response.status_code == 200
    assert response.json()["type"] == "instant"
    assert response.json()["intent"] == intent
    assert response.json()["session_id"] is None
    loop.investigate.assert_not_awaited()
    assert store.list_sessions() == []


@pytest.mark.parametrize(
    ("path", "body", "expected_status", "message_key"),
    [
        ("/api/agent/investigate", {"goal": "analyze 8.8.8.8"}, "active", "goal"),
        ("/api/chat", {"message": "analyze 8.8.8.8"}, "processing", "message"),
    ],
)
def test_non_intent_keeps_existing_investigation_response(tmp_path, path, body, expected_status, message_key):
    app, _, loop, _ = _client(tmp_path)

    with TestClient(app) as client:
        response = client.post(path, json=body)

    assert response.status_code == 200
    assert response.json() == {
        "session_id": "spy-session",
        "status": expected_status,
        message_key: "analyze 8.8.8.8",
    }
    loop.investigate.assert_awaited_once()


def test_agent_route_case_id_bypasses_intent_shortcut(tmp_path):
    app, _, loop, _ = _client(tmp_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/agent/investigate",
            json={"goal": "hello", "case_id": "case-17"},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "active"
    loop.investigate.assert_awaited_once()
    loop._chat_with_tools.assert_not_awaited()


def test_agent_route_playbook_id_bypasses_intent_shortcut(tmp_path):
    app, _, loop, _ = _client(tmp_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/agent/investigate",
            json={"goal": "hello", "playbook_id": "playbook-17"},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "active"
    loop.investigate.assert_awaited_once()
    loop._chat_with_tools.assert_not_awaited()


def test_chat_playbook_id_bypasses_intent_shortcut(tmp_path):
    app, _, loop, playbook_engine = _client(tmp_path, role="Incident Responder")

    with TestClient(app) as client:
        response = client.post(
            "/api/chat",
            json={"message": "hello", "playbook_id": "playbook-17"},
        )

    assert response.status_code == 200
    assert response.json()["session_id"] == "playbook-session"
    playbook_engine.start.assert_awaited_once()
    loop.investigate.assert_not_awaited()


def test_agent_route_keeps_role_authorization_for_greetings(tmp_path):
    app, _, loop, _ = _client(tmp_path, role="SOC Analyst Tier 1-2")

    with TestClient(app) as client:
        response = client.post("/api/agent/investigate", json={"goal": "hello"})

    assert response.status_code == 403
    loop.investigate.assert_not_awaited()
    loop._chat_with_tools.assert_not_awaited()


def test_chat_route_keeps_role_authorization_for_greetings(tmp_path):
    app, _, loop, _ = _client(tmp_path, role="SOC Analyst Tier 1-2")

    with TestClient(app) as client:
        response = client.post("/api/chat", json={"message": "hello"})

    assert response.status_code == 403
    loop.investigate.assert_not_awaited()
    loop._chat_with_tools.assert_not_awaited()


@pytest.mark.parametrize("path,field", [("/api/agent/investigate", "goal"), ("/api/chat", "message")])
@pytest.mark.parametrize(
    "role,message,expected_status,starts_investigation",
    [
        ("Incident Responder", "hello", 200, False),
        ("Incident Responder", "analyze 8.8.8.8", 403, False),
        ("Threat Hunter", "analyze 8.8.8.8", 200, True),
        ("admin", "analyze 8.8.8.8", 200, True),
        ("SOC Analyst Tier 1-2", "hello", 403, False),
        ("SOC Analyst Tier 1-2", "analyze 8.8.8.8", 403, False),
        ("SOC Analyst Tier 1-2", "asdfghjkl", 403, False),
        ("Team Lead", "hello", 403, False),
        ("Team Lead", "analyze 8.8.8.8", 403, False),
        ("Team Lead", "asdfghjkl", 403, False),
    ],
)
def test_role_intent_gate_contract(tmp_path, path, field, role, message, expected_status, starts_investigation):
    app, _, loop, _ = _client(tmp_path, role=role)

    with TestClient(app) as client:
        response = client.post(path, json={field: message})

    assert response.status_code == expected_status
    if role in {"SOC Analyst Tier 1-2", "Team Lead"}:
        loop._chat_with_tools.assert_not_awaited()
    elif message == "hello":
        assert response.json()["type"] == "instant"
        assert response.json()["intent"] == "converse"
        loop.investigate.assert_not_awaited()
    else:
        loop._chat_with_tools.assert_awaited_once()
        if starts_investigation:
            loop.investigate.assert_awaited_once()
        else:
            loop.investigate.assert_not_awaited()


@pytest.mark.parametrize("role", ["SOC Analyst Tier 1-2", "Team Lead"])
@pytest.mark.parametrize(
    "path,payload",
    [
        ("/api/agent/investigate", {"goal": "analyze 8.8.8.8"}),
        ("/api/chat", {"message": "analyze 8.8.8.8"}),
    ],
)
def test_denied_roles_get_403_before_missing_agent_loop(tmp_path, role, path, payload):
    app, _, _, _ = _client(tmp_path, role=role)
    app.state.agent_loop = None

    with TestClient(app) as client:
        response = client.post(path, json=payload)

    assert response.status_code == 403


def test_non_ioc_new_message_returns_instant_clarify_without_investigation(tmp_path):
    app, store, loop, _ = _client(tmp_path)

    with TestClient(app) as client:
        response = client.post("/api/agent/investigate", json={"goal": "asdfghjkl"})

    assert response.status_code == 200
    assert response.json()["type"] == "instant"
    assert response.json()["intent"] == "clarify"
    assert response.json()["session_id"] is None
    loop.investigate.assert_not_awaited()
    assert store.list_sessions() == []


@pytest.mark.parametrize(
    ("message", "intent", "investigate_calls"),
    [
        ("asdfghjkl", "clarify", 0),
        ("hello there", "converse", 0),
    ],
)
def test_session_followup_classifies_only_greeting_help(
    tmp_path, message, intent, investigate_calls
):
    app, _, loop, _ = _client(tmp_path)
    app.state.agent_store = SimpleNamespace(
        get_session=lambda session_id, user_id=None: {
            "id": session_id,
            "goal": "analyze 8.8.8.8",
            "status": "completed",
            "case_id": None,
        }
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/chat",
            json={"message": message, "session_id": "previous-session"},
        )

    assert response.status_code == 200
    if intent:
        assert response.json()["type"] == "instant"
        assert response.json()["intent"] == intent
        assert response.json()["session_id"] is None
    else:
        assert response.json()["status"] == "processing"
        assert response.json()["session_id"] == "spy-session"
    assert loop.investigate.await_count == investigate_calls


def test_agent_chat_template_handles_instant_replies():
    template = Path("templates/agent_chat.html").read_text(encoding="utf-8")

    assert "data.type !== 'instant'" in template
    assert "renderInstantReply(data, btn)" in template
