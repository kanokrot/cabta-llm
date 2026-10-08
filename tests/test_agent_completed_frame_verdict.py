from __future__ import annotations

import json
from pathlib import Path

from src.web.visibility import serialize_agent_session, serialize_websocket_frame
from src.web.websocket import _stored_agent_evidence, _stored_agent_verdict


def test_agent_completed_frame_keeps_scored_verdict_and_omits_unscored_verdict():
    completed = serialize_websocket_frame(
        {"type": "completed", "summary": "done", "steps": 7, "verdict": "MALICIOUS",
         "verdict_source": {"tool": "investigate_ioc", "step": 0}},
        role="admin",
        flow="websocket_agent",
    )
    no_verdict = serialize_websocket_frame(
        {"type": "completed", "summary": "done", "verdict": None},
        role="admin",
        flow="websocket_agent",
    )

    assert completed == {
        "type": "completed", "summary": "done", "verdict": "MALICIOUS",
        "steps": 7,
        "verdict_source": {"tool": "investigate_ioc", "step": 0},
    }
    assert no_verdict == {"type": "completed", "summary": "done"}


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
            "content": json.dumps({
                "action": "final_answer", "verdict": "SUSPICIOUS",
                "verdict_source": {"tool": "investigate_ioc", "step": 0},
            }),
        },
    ]

    assert _stored_agent_verdict(steps) == "SUSPICIOUS"
    assert _stored_agent_verdict(steps[:1]) is None
    assert _stored_agent_verdict(
        [{"step_type": "final_answer", "content": json.dumps({"verdict": None})}]
    ) is None


def test_missing_verdict_source_hides_verdict_from_history_websocket_and_replay():
    step = {
        "step_number": 0,
        "step_type": "final_answer",
        "content": json.dumps({
            "action": "final_answer",
            "answer": "Verdict: MALICIOUS",
            "verdict": "MALICIOUS",
            "evidence": {"scoring_sources": []},
        }),
    }
    history = serialize_agent_session(
        {"id": "session-1", "goal": "Investigate example.test"},
        steps=[step],
        role="admin",
    )["history"][-1]
    frame = serialize_websocket_frame(
        {
            "type": "completed",
            "summary": "Verdict: MALICIOUS",
            "verdict": "MALICIOUS",
            "evidence": {"scoring_sources": []},
        },
        role="admin",
        flow="websocket_agent",
    )

    assert "No scoring-engine result" in history["content"]
    assert "Verdict: MALICIOUS" not in history["content"]
    assert not {"verdict", "verdict_source", "evidence"} & history.keys()
    assert not {"verdict", "verdict_source", "evidence"} & frame.keys()
    assert _stored_agent_verdict([step]) is None
    assert _stored_agent_evidence([step]) is None


def test_live_and_replayed_agent_completed_frames_use_scored_verdict():
    root = Path(__file__).parents[1]
    agent_loop = (root / "src" / "agent" / "agent_loop.py").read_text(encoding="utf-8")
    websocket = (root / "src" / "web" / "websocket.py").read_text(encoding="utf-8")

    assert "verdict_source = extract_deterministic_verdict_source(state.findings)" in agent_loop
    assert "extract_deterministic_verdict(state.findings)" in agent_loop
    assert "if verdict_source is not None else None" in agent_loop
    assert websocket.count("_stored_agent_verdict(") >= 3
    assert 'final_decision["verdict_source"] = verdict_source' in agent_loop
    assert "serialize_verdict_source(decision.get(\"verdict_source\"))" in websocket
