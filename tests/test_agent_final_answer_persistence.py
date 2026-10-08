from __future__ import annotations

import json
from types import SimpleNamespace
import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentState
from src.web.visibility import serialize_agent_session


class _Store:
    def __init__(self, *, fail_final_answer=False):
        self.steps = []
        self.status = None
        self.fail_final_answer = fail_final_answer

    def add_step(self, session_id, step_number, step_type, content, **kwargs):
        if step_type == "final_answer" and self.fail_final_answer:
            raise OSError("write failed")
        self.steps.append({
            "session_id": session_id,
            "step_number": step_number,
            "step_type": step_type,
            "content": content,
        })

    def update_session_status(self, session_id, status, summary):
        self.status = status

    def update_session_findings(self, session_id, findings):
        self.findings = findings


class _Selector:
    def has_successful_evidence(self, state):
        return True

    def get_enrichment_mcp_tools(self, *args):
        return []


class _Tools:
    def get_tool(self, name):
        return SimpleNamespace(requires_approval=False)


def _scoring_result():
    return {
        "ioc": "8.8.8.8",
        "ioc_type": "ipv4",
        "threat_score": 0,
        "verdict": "CLEAN",
        "sources": {},
        "coverage": {},
    }


async def _run_loop(state, decisions, store):
    loop = AgentLoop.__new__(AgentLoop)
    loop.store = store
    loop.tools = _Tools()
    loop._active_sessions = {state.session_id: state}
    loop._approval_events = {}
    loop._subscribers = {}
    loop._main_loop = None
    loop.notification_manager = None
    loop.ollama_endpoint = "test"
    loop.ollama_model = "test"
    loop.tool_selector = _Selector()
    loop._notify = lambda *args, **kwargs: None

    async def think(_state):
        return decisions.pop(0)

    async def act(_state, _decision):
        return _scoring_result()

    async def summary(_state):
        return "Investigation summary"

    loop._think = think
    loop._act = act
    loop._generate_summary = summary
    await loop._run_loop(state.session_id)


@pytest.mark.asyncio
async def test_duplicate_call_completion_persists_scored_final_answer_once():
    state = AgentState(session_id="new-session", goal="analyze 8.8.8.8", max_steps=10)
    tool_call = {
        "action": "use_tool",
        "tool": "investigate_ioc",
        "params": {"ioc": "8.8.8.8"},
    }
    store = _Store()

    await _run_loop(state, [dict(tool_call), dict(tool_call)], store)

    finals = [step for step in store.steps if step["step_type"] == "final_answer"]
    assert store.status == "completed"
    assert len(finals) == 1
    decision = json.loads(finals[0]["content"])
    assert decision["answer"] == "Investigation summary"
    assert decision["verdict"] == "CLEAN"
    assert decision["verdict_source"] == {"tool": "investigate_ioc", "step": 0}
    assert decision["evidence"]["ioc"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_normal_final_answer_path_does_not_save_a_second_step():
    state = AgentState(session_id="normal-final", goal="hello", max_steps=10)
    store = _Store()

    await _run_loop(state, [{"action": "final_answer", "answer": "Hello"}], store)

    finals = [step for step in store.steps if step["step_type"] == "final_answer"]
    assert store.status == "completed"
    assert len(finals) == 1
    decision = json.loads(finals[0]["content"])
    assert decision == {
        "answer": "Hello\n\nNo scoring-engine result \u2014 this is an LLM summary, not a verdict."
    }
    assert "verdict_source" not in decision


@pytest.mark.asyncio
async def test_final_answer_write_failure_does_not_fail_completed_session():
    state = AgentState(session_id="write-failure", goal="hello", max_steps=10)
    store = _Store(fail_final_answer=True)
    await _run_loop(
        state, [{"action": "final_answer", "answer": "Hello"}], store,
    )
    assert store.status == "completed"


def test_legacy_completed_session_rebuilds_scoring_provenance_from_findings():
    finding = {
        "type": "tool_result",
        "tool": "investigate_ioc",
        "step": 0,
        "result": _scoring_result(),
    }
    serialized = serialize_agent_session(
        {
            "id": "legacy-session",
            "status": "completed",
            "goal": "analyze 8.8.8.8",
            "summary": "Stored investigation summary",
            "findings": [finding],
        },
        steps=[],
        role="admin",
    )

    assert serialized["history"][-1]["role"] == "agent"
    assert serialized["history"][-1]["verdict"] == "CLEAN"
    assert serialized["history"][-1]["verdict_source"] == {
        "tool": "investigate_ioc", "step": 0,
    }
    assert serialized["history"][-1]["evidence"]["ioc"] == "8.8.8.8"


def test_legacy_completed_session_without_complete_provenance_shows_notice():
    serialized = serialize_agent_session(
        {
            "id": "legacy-session",
            "status": "completed",
            "goal": "analyze 8.8.8.8",
            "summary": "Stored summary must not supply a verdict",
            "findings": [{
                "type": "tool_result",
                "tool": "investigate_ioc",
                "result": {"verdict": "CLEAN"},
            }],
        },
        steps=[],
        role="admin",
    )

    assert serialized["history"][-1] == {
        "role": "agent",
        "content": "This session completed before an answer was saved.",
    }
    assert "verdict" not in serialized["history"][-1]
