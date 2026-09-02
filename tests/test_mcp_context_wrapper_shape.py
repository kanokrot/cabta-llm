"""Regression coverage for resolving MCP-wrapped playbook results."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agent.agent_store import AgentStore
from src.agent.mcp_client import MCPClientManager
from src.agent.playbook_engine import PlaybookEngine, _resolve_var


class _MCPAgentLoop:
    """Minimal AgentLoop-compatible adapter backed by an MCP manager."""

    def __init__(self, mcp_client):
        self.config = {}
        self.mcp_client = mcp_client
        self._notify = MagicMock()

    async def run_tool(self, tool_name, params):
        assert tool_name.startswith("mcp:")
        server_name, remote_tool = tool_name[4:].split("/", 1)
        return await self.mcp_client.call_tool(server_name, remote_tool, params)


@pytest.mark.asyncio
async def test_mcp_result_wrapper_is_stored_in_playbook_context(tmp_path):
    """The engine stores the wrapper while both template paths resolve."""
    tool_response = {
        "status": "success",
        "error": None,
        "data": {"host": "192.0.2.10", "process_list": {"stdout": "root 1"}},
    }
    wrapped_response = {
        "result": tool_response,
        "server": "remote_tools",
        "tool": "process_list_collect",
    }

    mcp_client = MagicMock(spec=MCPClientManager)
    mcp_client.call_tool = AsyncMock(return_value=wrapped_response)
    agent_loop = _MCPAgentLoop(mcp_client)
    store = AgentStore(str(tmp_path / "agent.db"))
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)
    playbook_id = engine.register_playbook(
        name="MCP context wrapper characterization",
        description="Minimal mocked MCP playbook",
        steps=[
            {
                "name": "collect_processes",
                "tool": "mcp:remote_tools/process_list_collect",
                "params": {
                    "host": "192.0.2.10",
                    "username": "analyst",
                    "key_path": "mock-key-path",
                },
                "requires_approval": True,
            }
        ],
    )

    session_id = await engine.execute(playbook_id, {})
    captured = {}

    async def capture_continuation(
        session_id,
        playbook_id,
        playbook,
        steps,
        step_map,
        context,
        current_step,
        step_number,
        case_id,
    ):
        captured["context"] = context
        return session_id

    engine._run_step_loop = AsyncMock(side_effect=capture_continuation)
    await engine.execute_from_step(session_id, approved=True, approved_by="test")

    mcp_client.call_tool.assert_awaited_once_with(
        "remote_tools",
        "process_list_collect",
        {
            "host": "192.0.2.10",
            "username": "analyst",
            "key_path": "mock-key-path",
        },
    )
    context = captured["context"]
    assert context["collect_processes"] == wrapped_response
    assert context["collect_processes"]["result"]["data"]["host"] == "192.0.2.10"
    assert _resolve_var("collect_processes.result.data.host", context) == "192.0.2.10"
    assert _resolve_var("collect_processes.data.host", context) == "192.0.2.10"


def test_resolve_var_preserves_normal_non_mcp_path():
    context = {"local_step": {"data": {"host": "local-host"}}}

    assert _resolve_var("local_step.data.host", context) == "local-host"


def test_resolve_var_falls_back_through_mcp_result_wrapper():
    context = {
        "remote_step": {
            "result": {"data": {"host": "remote-host"}},
            "server": "remote_tools",
            "tool": "system_info_collect",
        }
    }

    assert _resolve_var("remote_step.data.host", context) == "remote-host"


def test_resolve_var_preserves_explicit_mcp_result_path():
    context = {
        "remote_step": {
            "result": {"data": {"host": "remote-host"}},
            "server": "remote_tools",
            "tool": "system_info_collect",
        }
    }

    assert _resolve_var("remote_step.result.data.host", context) == "remote-host"


def test_resolve_var_does_not_fallback_for_ordinary_result_dict():
    context = {
        "local_step": {
            "result": {"data": {"host": "local-host"}},
        }
    }

    assert _resolve_var("local_step.data.host", context) is None
