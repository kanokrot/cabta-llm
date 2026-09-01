"""Regression coverage for approval resume of for_each playbook steps."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine, PlaybookStep


def _build_paused_engine(tmp_path, step_dict, context, tool_result):
    store = AgentStore(str(tmp_path / "agent.db"))
    agent_loop = MagicMock()
    agent_loop.config = {}
    agent_loop.run_tool = AsyncMock(side_effect=tool_result)

    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    step = PlaybookStep.from_dict(step_dict)
    playbook_id = "approval-resume-test"
    engine._cache[playbook_id] = {
        "id": playbook_id,
        "name": "Approval resume test",
        "_parsed_steps": [step],
    }

    session_id = store.create_session(
        goal="Approval resume test",
        playbook_id=playbook_id,
    )
    store.update_session_metadata(session_id, {
        "context": context,
        "pending_step_name": step.name,
        "step_number": 3,
        "case_id": None,
    })
    store.update_session_status(session_id, "waiting_approval")

    captured = {}

    async def capture_continuation(
        session_id, playbook_id, pb, steps, step_map, context,
        current_step, step_number, case_id,
    ):
        captured["context"] = context
        captured["current_step"] = current_step
        return session_id

    engine._run_step_loop = AsyncMock(side_effect=capture_continuation)
    return engine, agent_loop, session_id, captured


@pytest.mark.asyncio
async def test_execute_from_step_resumes_for_each_once_per_item(tmp_path):
    async def tool_result(tool_name, params):
        return {
            "item": params["target"],
            "malicious": params["target"] == "host-b",
            "suspicious_keywords": (
                ["encoded-command"] if params["target"] == "host-a" else []
            ),
        }

    items = ["host-a", "host-b", "host-c"]
    engine, agent_loop, session_id, captured = _build_paused_engine(
        tmp_path,
        {
            "name": "remote_collect",
            "tool": "remote_collect",
            "for_each": "remote_hosts",
            "params": {"target": "{{item}}"},
            "requires_approval": True,
        },
        {"remote_hosts": items},
        tool_result,
    )

    await engine.execute_from_step(session_id, approved=True, approved_by="test")

    assert agent_loop.run_tool.await_count == len(items)
    sent_targets = [call.args[1]["target"] for call in agent_loop.run_tool.await_args_list]
    assert sent_targets == items
    assert "{{item}}" not in sent_targets

    context = captured["context"]
    assert len(context["remote_collect_results"]) == len(items)
    assert context["remote_collect_any_malicious"] is True
    assert context["remote_collect_any_suspicious"] is True
    assert context["remote_collect_items"] == items


@pytest.mark.asyncio
async def test_execute_from_step_keeps_single_approved_tool_call_behavior(tmp_path):
    async def tool_result(tool_name, params):
        return {"blocked": True, "ip": params["ip_address"]}

    engine, agent_loop, session_id, captured = _build_paused_engine(
        tmp_path,
        {
            "name": "block_malicious_ip",
            "tool": "block_ip",
            "params": {"ip_address": "{{target_ip}}"},
            "requires_approval": True,
        },
        {"target_ip": "203.0.113.10"},
        tool_result,
    )

    await engine.execute_from_step(session_id, approved=True, approved_by="test")

    agent_loop.run_tool.assert_awaited_once_with(
        "block_ip", {"ip_address": "203.0.113.10"},
    )
    context = captured["context"]
    assert context["block_malicious_ip"] == {
        "blocked": True,
        "ip": "203.0.113.10",
    }
    assert context["block_malicious_ip_blocked"] is True
    assert context["block_malicious_ip_ip"] == "203.0.113.10"
