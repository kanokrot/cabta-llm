"""Role-aware tool dispatch for playbooks started through the chat route."""

import json
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.agent.agent_loop import AgentLoop
from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine
from src.agent.tool_registry import ToolRegistry
from src.web.auth import get_current_user
from src.web.routes.chat import router as chat_router


def _run_chat_playbook(tmp_path, role):
    store = AgentStore(str(tmp_path / f"chat-playbook-{role.replace(' ', '-')}.db"))
    registry = ToolRegistry()
    registry.register_default_tools({})
    executed_block_calls = []

    async def record_block_call(**params):
        executed_block_calls.append(params)
        return {"status": "executed"}

    registry._executors["block_ip"] = record_block_call
    loop = AgentLoop(
        config={"ticketing": {"create_on_verdict": []}},
        tool_registry=registry,
        agent_store=store,
    )
    dispatched_roles = []
    real_run_tool = loop.run_tool

    async def record_dispatch(tool_name, params, role=None, context=None):
        dispatched_roles.append(role)
        return await real_run_tool(tool_name, params, role=role, context=context)

    loop.run_tool = record_dispatch
    engine = PlaybookEngine(loop, store)
    playbook_id = engine.register_playbook(
        name="Chat route containment test",
        description="Exercise role authorization through /api/chat.",
        steps=[{
            "name": "block_indicator",
            "tool": "block_ip",
            "params": {"ip_address": "203.0.113.45", "reason": "test"},
        }],
    )

    app = FastAPI()
    app.state.agent_loop = loop
    app.state.playbook_engine = engine
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 29,
        "email": "chat-test@example.test",
        "role": role,
    }
    app.include_router(chat_router, prefix="/api/chat")

    with TestClient(app) as client:
        response = client.post(
            "/api/chat",
            json={"message": "Run containment", "playbook_id": playbook_id},
        )
    assert response.status_code == 200
    session_id = response.json()["session_id"]

    deadline = time.monotonic() + 5
    session = store.get_session(session_id)
    while session["status"] not in {"completed", "failed"} and time.monotonic() < deadline:
        time.sleep(0.01)
        session = store.get_session(session_id)

    assert session["status"] == "completed"
    steps = store.get_steps(session_id)
    tool_result = json.loads(steps[0]["tool_result"])
    return dispatched_roles, executed_block_calls, tool_result


def test_chat_playbook_dispatch_passes_ir_and_denies_block_ip(tmp_path):
    roles, executed_calls, result = _run_chat_playbook(tmp_path, "Incident Responder")

    assert roles == ["Incident Responder"]
    assert result == {"error": "Tool is not allowed for this role"}
    assert executed_calls == []


def test_chat_playbook_admin_can_still_dispatch_block_ip(tmp_path):
    roles, executed_calls, result = _run_chat_playbook(tmp_path, "admin")

    assert roles == ["admin"]
    assert result == {"status": "executed"}
    assert executed_calls == [{"ip_address": "203.0.113.45", "reason": "test"}]
