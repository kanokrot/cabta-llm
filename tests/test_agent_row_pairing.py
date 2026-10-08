"""Regression coverage for live tool-call step pairing in AgentLoop."""

from types import SimpleNamespace

import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentState
from src.web.visibility import serialize_websocket_frame


class _Store:
    def add_step(self, *args, **kwargs):
        pass

    def update_session_status(self, *args, **kwargs):
        pass

    def update_session_findings(self, *args, **kwargs):
        pass


class _Selector:
    def has_successful_evidence(self, state):
        return True

    def __init__(self):
        self.enrichment_calls = 0

    def get_enrichment_mcp_tools(self, *args):
        self.enrichment_calls += 1
        if self.enrichment_calls == 1:
            return [("network_tools.dns_lookup", {"domain": "example.com"})]
        return []


class _Tools:
    def get_tool(self, _name):
        return SimpleNamespace(requires_approval=False)


@pytest.mark.asyncio
async def test_phase_and_tool_result_steps_pair_for_regular_enrichment_and_repeated_tools():
    state = AgentState(
        session_id="row-pairing",
        goal="analyze 8.8.8.8 and 1.1.1.1",
        max_steps=10,
    )
    decisions = [
        {"action": "use_tool", "tool": "investigate_ioc", "params": {"ioc": "8.8.8.8"}},
        {"action": "use_tool", "tool": "investigate_ioc", "params": {"ioc": "1.1.1.1"}},
        {"action": "final_answer", "answer": "Done"},
    ]
    loop = AgentLoop.__new__(AgentLoop)
    loop.store = _Store()
    loop.tools = _Tools()
    loop._active_sessions = {state.session_id: state}
    loop._approval_events = {}
    loop._subscribers = {}
    loop._main_loop = None
    loop.notification_manager = None
    loop.ollama_endpoint = "test"
    loop.ollama_model = "test"
    loop.tool_selector = _Selector()

    async def think(_state):
        return decisions.pop(0)

    async def act(_state, decision):
        if decision["tool"] == "investigate_ioc":
            return {
                "ioc": decision["params"]["ioc"],
                "verdict": "CLEAN",
                "threat_score": 0,
                "sources": {},
            }
        return {"records": []}

    async def summary(_state):
        return "Done"

    loop._think = think
    loop._act = act
    loop._generate_summary = summary

    serialized_frames = []

    def notify(_session_id, frame):
        serialized_frames.append(serialize_websocket_frame(
            frame, role="admin", flow="websocket_agent",
        ))

    loop._notify = notify
    await loop._run_loop(state.session_id)

    starts = [
        frame for frame in serialized_frames
        if frame.get("type") == "phase" and frame.get("phase") == "acting"
    ]
    results = [frame for frame in serialized_frames if frame.get("type") == "tool_result"]

    assert [frame["tool"] for frame in starts] == [
        "investigate_ioc", "network_tools.dns_lookup", "investigate_ioc",
    ]
    assert [frame["tool"] for frame in results] == [
        "investigate_ioc", "network_tools.dns_lookup", "investigate_ioc",
    ]
    assert [frame["step"] for frame in starts] == [0, 1, 2]
    assert [frame["step"] for frame in results] == [0, 1, 2]
    assert [start["step"] for start in starts] == [result["step"] for result in results]
