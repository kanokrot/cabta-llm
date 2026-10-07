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
    loop = SimpleNamespace(investigate=AsyncMock(return_value="spy-session"))
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
        ("/api/agent/investigate", {"goal": "hello"}, "greeting"),
        ("/api/agent/investigate", {"goal": "help"}, "help"),
        ("/api/agent/investigate", {"goal": "สวัสดี"}, "greeting"),
        ("/api/chat", {"message": "hello"}, "greeting"),
        ("/api/chat", {"message": "help"}, "help"),
        ("/api/chat", {"message": "สวัสดี"}, "greeting"),
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


def test_chat_route_keeps_role_authorization_for_greetings(tmp_path):
    app, _, loop, _ = _client(tmp_path, role="SOC Analyst Tier 1-2")

    with TestClient(app) as client:
        response = client.post("/api/chat", json={"message": "hello"})

    assert response.status_code == 403
    loop.investigate.assert_not_awaited()


def test_agent_chat_template_handles_instant_replies():
    template = Path("templates/agent_chat.html").read_text(encoding="utf-8")

    assert "data.type !== 'instant'" in template
    assert "renderInstantReply(data, btn)" in template
