"""Regression tests for local tool visibility serialization."""

from src.agent.mcp_tool_presentation import MCP_TOOL_PRESENTATION
from src.agent.mcp_tool_classification import MCP_TOOL_CLASSIFICATIONS
from src.agent.tool_registry import ToolRegistry
from src.web.visibility import serialize_tool_definition


UNAVAILABLE_SUMMARY = "Tool description is not available from the registered metadata."


def test_all_registerable_local_tools_keep_descriptions_as_summaries():
    registry = ToolRegistry()
    dependency = object()
    registry.register_default_tools(
        {},
        ioc_investigator=dependency,
        malware_analyzer=dependency,
        email_analyzer=dependency,
    )

    local_tools = registry.list_tools()
    assert len(local_tools) == 14

    serialized = [serialize_tool_definition(tool, role="admin") for tool in local_tools]
    assert all(item is not None for item in serialized)
    assert {item["name"] for item in serialized} == {tool.name for tool in local_tools}

    for item, tool in zip(serialized, local_tools):
        assert item["source"] == "local"
        assert item["description"] == tool.description
        assert item["summary"] == tool.description
        assert item["summary"] != UNAVAILABLE_SUMMARY


def test_mcp_presentation_inventory_remains_complete_and_unchanged():
    assert len(MCP_TOOL_CLASSIFICATIONS) == 63
    assert set(MCP_TOOL_PRESENTATION) == set(MCP_TOOL_CLASSIFICATIONS)
    assert all(item.summary != UNAVAILABLE_SUMMARY for item in MCP_TOOL_PRESENTATION.values())
