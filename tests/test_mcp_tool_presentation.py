"""Regression tests for UI-only MCP tool presentation metadata."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from pathlib import Path

import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentState
from src.agent.agent_store import AgentStore
from src.agent.mcp_tool_classification import (
    MCP_TOOL_CLASSIFICATIONS,
    decorate_mcp_tool,
)
from src.agent.mcp_tool_presentation import (
    MCP_TOOL_PRESENTATION,
    fallback_presentation,
)
from src.agent.tool_registry import ToolRegistry
from src.web.visibility import serialize_tool_definition


def test_all_registered_mcp_tools_have_unique_explicit_presentation():
    assert len(MCP_TOOL_CLASSIFICATIONS) == 63
    assert set(MCP_TOOL_PRESENTATION) == set(MCP_TOOL_CLASSIFICATIONS)

    for server in {server for server, _ in MCP_TOOL_PRESENTATION}:
        names = [
            item.display_name
            for (item_server, _), item in MCP_TOOL_PRESENTATION.items()
            if item_server == server
        ]
        assert len(names) == len(set(names)), server

    for item in MCP_TOOL_PRESENTATION.values():
        assert item.summary
        assert 1 <= len(item.examples) <= 4
        if item.logo:
            assert item.logo.startswith("/static/")
            assert "://" not in item.logo


def test_mcp_servers_details_are_scoped_to_the_mcp_page():
    template = Path("templates/mcp_servers.html").read_text(encoding="utf-8")
    assert "toolDetailsModal" in template
    assert "inputSchema" in template
    assert "textContent" in template
    assert "innerHTML" not in template.split("function showToolDetails", 1)[1].split("function checkServer", 1)[0]
    assert "templates/agent_chat.html" not in template
    assert "templates/agent_investigations.html" not in template


def test_registry_and_llm_keep_the_technical_name():
    registry = ToolRegistry()
    registry.register_mcp_tools(
        "network_tools",
        [{"name": "dns_lookup", "description": "DNS", "inputSchema": {}}],
    )

    tool = registry.get_tool("network_tools.dns_lookup")
    assert tool is not None
    assert tool.name == "network_tools.dns_lookup"
    assert registry.get_tools_for_llm()[0]["function"]["name"] == "network_tools.dns_lookup"


@pytest.mark.asyncio
async def test_mcp_dispatch_keeps_raw_function_name():
    registry = ToolRegistry()
    registry.register_mcp_tools(
        "network_tools",
        [{"name": "dns_lookup", "description": "DNS", "inputSchema": {}}],
    )
    mcp_client = SimpleNamespace(call_tool=AsyncMock(return_value={"ok": True}))
    loop = AgentLoop(
        config={},
        tool_registry=registry,
        agent_store=MagicMock(),
        mcp_client=mcp_client,
    )

    result = await loop.run_tool(
        "network_tools.dns_lookup",
        {"domain": "example.com"},
        role="Threat Hunter",
    )

    assert result == {"ok": True}
    mcp_client.call_tool.assert_awaited_once_with(
        "network_tools", "dns_lookup", {"domain": "example.com"}
    )


def test_discovery_and_api_serialization_add_ui_fields_only():
    discovered = decorate_mcp_tool(
        "network_tools",
        {"name": "dns_lookup", "description": "DNS", "inputSchema": {}},
    )
    assert discovered["name"] == "dns_lookup"
    assert discovered["category"] == "network"
    assert discovered["display_name"] == "DNS Lookup"
    assert discovered["ui_category"] == "Network"
    assert discovered["icon"] == "network"

    serialized = serialize_tool_definition({
        **discovered,
        "name": "network_tools.dns_lookup",
        "source": "network_tools",
    }, role="admin")
    assert serialized["name"] == "network_tools.dns_lookup"
    assert serialized["category"] == "network"
    assert serialized["display_name"] == "DNS Lookup"
    assert serialized["ui_category"] == "Network"
    assert serialized["icon"] == "network"
    assert serialized["summary"] == "Perform DNS lookups for the requested record types."
    assert serialized["examples"]
    assert serialized["inputSchema"] == {}


def test_unmapped_tool_has_ui_fallback_without_changing_technical_name():
    fallback = fallback_presentation("new_tool_name", "network")
    assert fallback.display_name == "New Tool Name"
    assert fallback.ui_category == "Network"
    assert fallback.icon == "network"


def test_approval_audit_and_agent_step_keep_technical_id(tmp_path):
    technical_id = "remote_tools.process_list_collect"
    state = AgentState(session_id="session", goal="test")
    state.request_approval({"tool": technical_id, "params": {}}, "approval")
    assert state.pending_approval["action"]["tool"] == technical_id

    store = AgentStore(str(tmp_path / "agent.db"))
    session_id = store.create_session(goal="test")
    store.add_step(
        session_id,
        1,
        "tool_call",
        "test",
        tool_name=technical_id,
    )
    store.add_audit_entry(
        session_id=session_id,
        action=technical_id,
        action_type="tool_call",
        requires_approval=True,
    )

    step = store.get_steps(session_id)[0]
    audit = store.get_audit_log(session_id)[0]
    assert step["tool_name"] == technical_id
    assert audit["action"] == technical_id
