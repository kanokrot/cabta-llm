"""Regression coverage for failed and denied playbook tool calls in summaries."""

import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine
from src.agent.tool_registry import ToolRegistry
from src.web.visibility import INCIDENT_RESPONDER


class _Dispatcher:
    def __init__(self, result):
        self.result = result
        self.config = {}

    async def run_tool(self, tool_name, params, **kwargs):
        return self.result

    def _notify(self, session_id, payload):
        pass


async def _run_steps(tmp_path, label, steps, dispatcher, *, role=None, input_data=None):
    store = AgentStore(str(tmp_path / f"{label}.db"))
    engine = PlaybookEngine(dispatcher, store)
    playbook_id = engine.register_playbook(
        f"{label} playbook", "summary test", steps,
    )
    session_id = await engine.execute(
        playbook_id, input_data or {}, user_id=17 if role else None, role=role,
    )
    return store, session_id


@pytest.mark.asyncio
async def test_clean_playbook_summary_remains_byte_identical(tmp_path):
    store, session_id = await _run_steps(
        tmp_path,
        "clean",
        [{"name": "lookup", "tool": "lookup"}],
        _Dispatcher({}),
    )

    session = store.get_session(session_id)
    assert session["status"] == "completed"
    assert session["summary"] == "Playbook 'clean playbook' completed (1 steps executed)"


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [None, INCIDENT_RESPONDER], ids=["role-none", "role-ir"])
async def test_denied_tool_is_named_in_playbook_summary(tmp_path, role):
    class DenyingDispatcher(_Dispatcher):
        async def run_tool(self, tool_name, params, **kwargs):
            return {"error": "Tool is not allowed for this role"}

    store, session_id = await _run_steps(
        tmp_path,
        f"denied-{role or 'none'}",
        [
            {"name": "restricted_lookup", "tool": "restricted_lookup"},
            {"name": "document", "action": "final_answer", "description": "done"},
        ],
        DenyingDispatcher(None),
        role=role,
    )

    session = store.get_session(session_id)
    assert session["status"] == "completed"
    assert "WARNING: 1 step(s) failed or were denied: restricted_lookup" in session["summary"]


@pytest.mark.asyncio
async def test_for_each_partial_errors_name_step_once(tmp_path):
    class PartialDispatcher(_Dispatcher):
        async def run_tool(self, tool_name, params, **kwargs):
            if params["item"] == "bad":
                return {"error": "denied"}
            return {"ok": True}

    store, session_id = await _run_steps(
        tmp_path,
        "partial-for-each",
        [
            {
                "name": "check_items",
                "tool": "check_item",
                "for_each": "items",
                "params": {"item": "{{item}}"},
            },
            {"name": "document", "action": "final_answer", "description": "done"},
        ],
        PartialDispatcher(None),
        input_data={"items": ["good", "bad", "also-good"]},
    )

    session = store.get_session(session_id)
    assert session["status"] == "completed"
    assert "WARNING: 1 step(s) failed or were denied: check_items" in session["summary"]


@pytest.mark.asyncio
async def test_tool_exception_is_reported_as_failed_step(tmp_path):
    class RaisingDispatcher(_Dispatcher):
        async def run_tool(self, tool_name, params, **kwargs):
            raise RuntimeError("offline dispatcher failure")

    store, session_id = await _run_steps(
        tmp_path,
        "exception",
        [{"name": "offline_lookup", "tool": "offline_lookup"}],
        RaisingDispatcher(None),
    )

    session = store.get_session(session_id)
    assert session["status"] == "completed"
    assert "WARNING: 1 step(s) failed or were denied: offline_lookup" in session["summary"]


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [None, INCIDENT_RESPONDER], ids=["role-none", "role-ir"])
async def test_real_dispatcher_denial_is_reported_for_role_paths(tmp_path, role):
    store = AgentStore(str(tmp_path / f"real-dispatch-{role or 'none'}.db"))
    mcp = _FakeMCP()
    loop = AgentLoop(
        config={}, tool_registry=ToolRegistry(), agent_store=store, mcp_client=mcp,
    )
    engine = PlaybookEngine(loop, store)
    playbook_id = engine.register_playbook(
        "Dispatcher denial", "test", [
            {"name": "unclassified_lookup", "tool": "mcp:unknown_server/unknown_tool"},
        ],
    )
    session_id = await engine.execute(playbook_id, {}, role=role)

    session = store.get_session(session_id)
    assert session["status"] == "completed"
    assert "WARNING: 1 step(s) failed or were denied: unclassified_lookup" in session["summary"]
    assert mcp.calls == []


class _FakeMCP:
    def __init__(self):
        self.calls = []

    async def call_tool(self, server, tool, params):
        self.calls.append((server, tool, params))
        if tool == "threatfox_ioc_lookup":
            return {"malicious": True, "verdict": "MALICIOUS", "ioc": params.get("indicator")}
        return {"ok": True, "malicious": False}


@pytest.mark.asyncio
async def test_alert_triage_real_dispatcher_offline_malicious_path(tmp_path):
    store = AgentStore(str(tmp_path / "alert-triage.db"))
    mcp = _FakeMCP()
    loop = AgentLoop(
        config={"agent": {"max_steps": 20}, "ticketing": {"create_on_verdict": []}},
        tool_registry=ToolRegistry(),
        agent_store=store,
        mcp_client=mcp,
    )
    loop.tools.register_default_tools({})
    engine = PlaybookEngine(loop, store)
    session_id = await engine.execute(
        "alert_triage",
        {"alert_text": "Suspicious connection to 203.0.113.77"},
        user_id=17,
        role=INCIDENT_RESPONDER,
    )

    parent = store.get_session(session_id)
    children = [
        session for session in store.list_sessions()
        if session.get("playbook_id") == "incident_response"
    ]
    assert parent["status"] == "completed"
    assert children, "MALICIOUS fake threat intel should trigger incident_response"
    child = children[0]
    assert child["user_id"] == 17
    assert child["metadata"].get("kind") == "playbook"

    parent_steps = store.get_steps(session_id)
    denied_parent_steps = [
        step["content"] for step in parent_steps
        if step.get("tool_result") and '"error"' in step["tool_result"]
    ]
    child_steps = store.get_steps(child["id"])
    denied_child_steps = [
        step.get("content", step.get("tool_name", ""))
        for step in child_steps
        if step.get("tool_result") and '"error"' in step["tool_result"]
    ]
    print({
        "parent_summary": parent["summary"],
        "incident_response_child_owned_by_ir_user_17": child["user_id"] == 17,
        "child_summary": child.get("summary"),
        "parent_denied_steps": denied_parent_steps,
        "child_denied_steps": denied_child_steps,
    })
    assert any("trigger_playbook" in step.get("step_type", "") for step in parent_steps)
    assert child["status"] == "completed"
    assert child.get("summary")
