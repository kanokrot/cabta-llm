from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.routes import agent as agent_routes
from src.web.visibility import serialize_agent_session


def test_agent_session_serializer_adds_playbook_type_without_changing_existing_fields():
    session = {
        "id": "playbook-1",
        "status": "completed",
        "goal": "Playbook: Incident Response",
        "summary": "done",
        "created_at": "2026-10-06T20:01:18Z",
        "playbook_id": "incident_response",
        "metadata": json.dumps({"kind": "playbook"}),
    }

    serialized = serialize_agent_session(session, steps=[], role="admin")

    assert serialized["session_type"] == "playbook"
    assert serialized["id"] == session["id"]
    assert serialized["status"] == session["status"]
    assert serialized["goal"] == session["goal"]
    assert serialized["summary"] == session["summary"]
    assert serialized["playbook_id"] == session["playbook_id"]
    assert serialized["history"] == [{"role": "user", "content": session["goal"]}]


def test_agent_session_list_includes_playbook_type_additively():
    session = {
        "id": "playbook-1",
        "status": "completed",
        "goal": "Playbook: Incident Response",
        "summary": "done",
        "playbook_id": "incident_response",
        "metadata": {"kind": "playbook"},
    }
    app = FastAPI()
    app.state.agent_store = SimpleNamespace(
        list_sessions=lambda **_kwargs: [session]
    )
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 17,
        "role": "admin",
        "is_active": 1,
    }
    app.include_router(agent_routes.router, prefix="/api/agent")

    with TestClient(app) as client:
        response = client.get("/api/agent/sessions")

    assert response.status_code == 200
    item = response.json()["sessions"][0]
    assert item["session_type"] == "playbook"
    assert item["id"] == session["id"]
    assert item["goal"] == session["goal"]
    assert item["playbook_id"] == session["playbook_id"]
    assert item["status"] == session["status"]


def test_agent_chat_session_loaders_select_endpoint_and_show_errors():
    template = (Path(__file__).parents[1] / "templates" / "agent_chat.html").read_text(
        encoding="utf-8"
    )
    switch = template.split("function switchSession(id)", 1)[1].split(
        "function renderPlaybookSession(data)", 1
    )[0]
    playbook_loader = template.split("function loadPlaybookSession(id, fromSidebar)", 1)[1].split(
        "function loadHistory(id)", 1
    )[0]
    history_loader = template.split("function loadHistory(id)", 1)[1].split(
        "function connectWebSocket(id)", 1
    )[0]

    assert "selectedSession.session_type === 'playbook'" in switch
    assert "loadPlaybookSession(id, true)" in switch
    assert "fetch('/api/playbooks/sessions/' + encodeURIComponent(id))" in playbook_loader
    assert "data.session_type === 'playbook'" in history_loader
    assert "fetch('/api/agent/sessions/' + encodeURIComponent(id))" in history_loader
    assert "showSessionLoadError" in playbook_loader
    assert "showSessionLoadError" in history_loader
    assert "HTTP 403" in playbook_loader
    assert "HTTP 403" in history_loader
    assert ".catch(function() {})" not in playbook_loader
    assert ".catch(function() {})" not in history_loader
