from __future__ import annotations

import asyncio
import copy
import json
from types import SimpleNamespace

from src.web.routes import agent as agent_routes


def _source_fixture():
    sources = {
        "threatfox": {"status": "flagged", "score": 90},
        "virustotal": {"status": "flagged", "score": 80},
    }
    sources.update(
        {f"clean-{index}": {"status": "clean", "score": 0} for index in range(8)}
    )
    sources.update(
        {f"responded-{index}": {"status": "ok", "score": 0} for index in range(2)}
    )
    sources.update(
        {
            f"error-{index}": {"status": "error", "error": "HTTP 503"}
            for index in range(5)
        }
    )
    sources.update(
        {
            f"na-{index}": {
                "status": "not_applicable",
                "not_applicable": True,
            }
            for index in range(11)
        }
    )
    return sources


def _raw_result():
    return {
        "ioc": "203.0.113.8",
        "ioc_type": "ipv4",
        "sources": _source_fixture(),
        "score_breakdown": {
            "threatfox": {
                "flagged": True,
                "score_used": 90,
                "weight": 1.0,
                "scored": True,
            }
        },
        "sources_flagged": 1,
        "sources_checked": 17,
    }


class _Store:
    def __init__(self, result):
        self.result = result

    def get_session(self, session_id, *, user_id):
        return {
            "id": session_id,
            "status": "completed",
            "goal": "Investigate IOC",
            "user_id": user_id or 1,
            "metadata": {},
            "findings": [],
        }

    def get_steps(self, session_id):
        return [
            {
                "id": "step-1",
                "step_number": 1,
                "step_type": "tool_call",
                "tool_name": "investigate_ioc",
                "tool_params": "{}",
                "tool_result": json.dumps(self.result),
            }
        ]


def _get_session_for_role(role):
    result = _raw_result()
    original = copy.deepcopy(result)
    app = SimpleNamespace(
        state=SimpleNamespace(agent_store=_Store(result), agent_loop=None)
    )
    request = SimpleNamespace(app=app)
    payload = asyncio.run(
        agent_routes.get_session(
            request,
            "session-1",
            {"id": 1, "role": role},
        )
    )
    return payload, result, original


def test_agent_session_source_counts_match_helper_for_admin_and_threat_hunter():
    for role in ("admin", "Threat Hunter"):
        payload, original_result, original_snapshot = _get_session_for_role(role)
        step = payload["steps"][0]
        counts = step["source_counts"]

        assert counts["flagged"] == 2
        assert counts["scored_flagged"] == 1
        assert counts["context_flagged"] == 1
        assert counts["responded"] == 12
        assert counts["errors"] == 5
        assert "sources" not in step
        assert "score_breakdown" not in step
        assert original_result == original_snapshot


def test_source_counts_match_steps_by_id_after_serializer_drops_a_step(monkeypatch):
    ioc_result = _raw_result()
    steps = [
        {
            "id": "step-message",
            "step_number": 1,
            "step_type": "message",
            "content": "Preparing investigation",
        },
        {
            "id": "step-ioc",
            "step_number": 2,
            "step_type": "tool_call",
            "tool_name": "investigate_ioc",
            "tool_params": "{}",
            "tool_result": json.dumps(ioc_result),
        },
        {
            "id": "step-other-tool",
            "step_number": 3,
            "step_type": "tool_call",
            "tool_name": "analyze_email",
            "tool_params": "{}",
            "tool_result": "{}",
        },
    ]
    app = SimpleNamespace(
        state=SimpleNamespace(
            agent_store=SimpleNamespace(
                get_session=lambda session_id, *, user_id: {
                    "id": session_id,
                    "status": "active",
                    "goal": "Investigate IOC",
                    "metadata": {},
                    "findings": [],
                },
                get_steps=lambda session_id: steps,
            ),
            agent_loop=None,
        )
    )
    request = SimpleNamespace(app=app)
    original_serializer = agent_routes.serialize_agent_session

    def serializer_drops_first_step(session, *, steps, live_state, role):
        payload = original_serializer(
            session, steps=steps, live_state=live_state, role=role
        )
        payload["steps"] = payload["steps"][1:]
        return payload

    monkeypatch.setattr(
        agent_routes, "serialize_agent_session", serializer_drops_first_step
    )
    payload = asyncio.run(
        agent_routes.get_session(
            request,
            "session-1",
            {"id": 1, "role": "Threat Hunter"},
        )
    )

    visible_steps = payload["steps"]
    assert [step["id"] for step in visible_steps] == ["step-ioc", "step-other-tool"]
    assert visible_steps[0]["source_counts"]["flagged"] == 2
    assert visible_steps[0]["source_counts"]["scored_flagged"] == 1
    assert visible_steps[0]["source_counts"]["context_flagged"] == 1
    assert "source_counts" not in visible_steps[1]


def test_agent_investigations_template_uses_only_serialized_source_counts():
    from pathlib import Path

    template = (
        Path(__file__).resolve().parents[1]
        / "templates"
        / "agent_investigations.html"
    ).read_text(encoding="utf-8")

    assert "step.source_counts" in template
    assert ": '—'" in template
    assert "result.sources_flagged" not in template
    assert "result.sources_checked" not in template
