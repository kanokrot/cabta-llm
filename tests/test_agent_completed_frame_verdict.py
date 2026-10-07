from __future__ import annotations

import json
from pathlib import Path

from src.web.visibility import serialize_websocket_frame
from src.web.websocket import _stored_agent_verdict


def test_agent_completed_frame_keeps_scored_verdict_and_null():
    completed = serialize_websocket_frame(
        {"type": "completed", "summary": "done", "verdict": "MALICIOUS"},
        role="admin",
        flow="websocket_agent",
    )
    no_verdict = serialize_websocket_frame(
        {"type": "completed", "summary": "done", "verdict": None},
        role="admin",
        flow="websocket_agent",
    )

    assert completed == {"type": "completed", "summary": "done", "verdict": "MALICIOUS"}
    assert no_verdict == {"type": "completed", "summary": "done", "verdict": None}


def test_playbook_completed_frame_does_not_gain_agent_verdict_field():
    frame = serialize_websocket_frame(
        {"type": "completed", "summary": "playbook done", "verdict": "MALICIOUS"},
        role="admin",
        flow="websocket_playbook",
    )

    assert frame == {"type": "completed", "summary": "playbook done"}


def test_late_client_verdict_comes_from_persisted_final_answer_decision():
    steps = [
        {"step_type": "tool_call", "content": json.dumps({"verdict": "CLEAN"})},
        {
            "step_type": "final_answer",
            "content": json.dumps({"action": "final_answer", "verdict": "SUSPICIOUS"}),
        },
    ]

    assert _stored_agent_verdict(steps) == "SUSPICIOUS"
    assert _stored_agent_verdict(steps[:1]) is None
    assert _stored_agent_verdict(
        [{"step_type": "final_answer", "content": json.dumps({"verdict": None})}]
    ) is None


def test_live_and_replayed_agent_completed_frames_use_scored_verdict():
    root = Path(__file__).parents[1]
    agent_loop = (root / "src" / "agent" / "agent_loop.py").read_text(encoding="utf-8")
    websocket = (root / "src" / "web" / "websocket.py").read_text(encoding="utf-8")

    assert '"verdict": extract_deterministic_verdict(state.findings)' in agent_loop
    assert websocket.count("_stored_agent_verdict(") >= 3
