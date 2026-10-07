"""Raw, deterministic observations of the Agent Chat HTTP route."""

import json
import sqlite3
import threading
import time

from fastapi.testclient import TestClient


MESSAGES = [
    "hello",
    "hi",
    "สวัสดี",
    "help",
    "/help",
    "what can you do?",
    "ช่วยอะไรได้บ้าง",
    "analyze 8.8.8.8",
    "asdfghjkl",
    "",
]


def test_agent_chat_conversation_probe(monkeypatch, tmp_path, capsys):
    """Print each real HTTP response and the session/LLM effects it produced."""
    import src.agent.agent_store as agent_store_module
    import src.web.app as app_module
    from src.web.routes import chat as chat_routes

    db_path = tmp_path / "agent.db"
    original_agent_store = agent_store_module.AgentStore

    class TempAgentStore(original_agent_store):
        def __init__(self, db_path_override=None):
            super().__init__(str(db_path_override or db_path))

    monkeypatch.setattr(agent_store_module, "AgentStore", TempAgentStore)
    monkeypatch.setattr(app_module, "initialize_ticketing_db", lambda: None)

    async def no_mcp_autoconnect(_app):
        return None

    monkeypatch.setattr(app_module, "_auto_connect_mcp_servers", no_mcp_autoconnect)

    app = app_module.create_app()
    app.dependency_overrides[chat_routes.get_current_user] = lambda: {
        "id": 424242,
        "username": "probe-admin",
        "email": "probe-admin@example.invalid",
        "role": "admin",
        "is_active": 1,
    }

    llm_calls = 0
    llm_lock = threading.Lock()

    async def fixed_think(_state):
        nonlocal llm_calls
        with llm_lock:
            llm_calls += 1
        return {
            "action": "final_answer",
            "answer": "Deterministic probe response.",
            "verdict": "UNKNOWN",
            "reasoning": "Fixed test double.",
        }

    monkeypatch.setattr(app.state.agent_loop, "_think", fixed_think)

    def session_count():
        with sqlite3.connect(db_path) as connection:
            row = connection.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()
            return int(row[0])

    with TestClient(app) as client:
        for message in MESSAGES:
            sessions_before = session_count()
            calls_before = llm_calls
            response = client.post("/api/chat", json={"message": message})
            body = response.text
            session_id = None
            if response.status_code == 200:
                try:
                    session_id = response.json().get("session_id")
                except (ValueError, AttributeError):
                    pass

            if session_id:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    session = app.state.agent_store.get_session(session_id)
                    if session and session.get("status") in {"completed", "failed"}:
                        break
                    time.sleep(0.01)
                steps = app.state.agent_store.get_steps(session_id)
                tools_called = [
                    step.get("tool_name")
                    for step in steps
                    if step.get("step_type") in {"tool_call", "tool_result"}
                    and step.get("tool_name")
                ]
            else:
                tools_called = []

            created_sessions = session_count() - sessions_before
            llm_calls_for_request = llm_calls - calls_before
            print(json.dumps({
                "message": message,
                "http_status": response.status_code,
                "response_body_raw": body,
                "llm_calls": llm_calls_for_request,
                "sessions_created": created_sessions,
                "tools_called": tools_called,
            }, ensure_ascii=True))
            assert response.status_code < 500, f"Unexpected server error for {message!r}: {body}"

    captured = capsys.readouterr()
    print(captured.out, end="")
