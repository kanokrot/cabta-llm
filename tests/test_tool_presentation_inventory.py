from __future__ import annotations

from src.agent.mcp_tool_classification import MCP_TOOL_CLASSIFICATIONS
from src.agent.mcp_tool_presentation import (
    ADDITIONAL_STATIC_MCP_PRESENTATION,
    MCP_TOOL_PRESENTATION,
    MCP_SERVER_GROUP_LABELS,
    fallback_presentation,
    get_mcp_tool_presentation,
)
from src.agent.local_tool_presentation import LOCAL_TOOL_PRESENTATION
from src.agent.tool_registry import ToolRegistry
from src.web.visibility import serialize_tool_definition


def test_static_mcp_tool_inventory_has_explicit_user_presentation():
    static_tools = set(MCP_TOOL_CLASSIFICATIONS) | set(ADDITIONAL_STATIC_MCP_PRESENTATION)

    assert len(MCP_TOOL_CLASSIFICATIONS) == 67
    assert static_tools == set(MCP_TOOL_PRESENTATION) | set(ADDITIONAL_STATIC_MCP_PRESENTATION)
    for server_name, raw_name in static_tools:
        presentation = get_mcp_tool_presentation(server_name, raw_name)
        assert presentation.display_name
        assert presentation.display_name != raw_name
        assert presentation.ui_category
        assert presentation.summary


def test_unclassified_static_vulnerability_tool_has_specific_presentation():
    presentation = get_mcp_tool_presentation(
        "vulnerability-tools", "ssl_vulnerability_check", "mcp_unclassified",
    )

    assert presentation.display_name == "SSL/TLS Vulnerability Check"
    assert presentation.ui_category == "OSINT"
    assert "TLS" in presentation.summary


def test_fallback_presentation_turns_underscores_into_readable_words():
    presentation = fallback_presentation("new_tool_name", "network")

    assert presentation.display_name == "New Tool Name"
    assert "." not in presentation.display_name
    assert "_" not in presentation.display_name


def test_all_static_local_tools_have_user_summaries_and_local_group_label():
    registry = ToolRegistry()
    dependency = object()
    registry.register_default_tools(
        {}, ioc_investigator=dependency, malware_analyzer=dependency,
        email_analyzer=dependency,
    )

    assert len(LOCAL_TOOL_PRESENTATION) == 14
    for tool in registry.list_tools():
        presentation = LOCAL_TOOL_PRESENTATION[tool.name]
        assert presentation.summary
        assert presentation.summary.endswith(".")
        assert presentation.display_name != tool.name
        assert not presentation.summary.lower().startswith(("returns ", "executes ", "registers "))
        serialized = serialize_tool_definition(tool, role="admin")
        assert serialized["summary"] == presentation.summary
        assert serialized["group_label"] == "Local"


def test_mcp_group_labels_cover_all_nine_classified_servers_and_unknowns_fallback():
    assert set(MCP_SERVER_GROUP_LABELS) == {server for server, _ in MCP_TOOL_CLASSIFICATIONS}
    assert MCP_SERVER_GROUP_LABELS["osint_tools"] == "OSINT"
    assert MCP_SERVER_GROUP_LABELS["threat_intel_tools"] == "Threat Intel"

    unknown = serialize_tool_definition({
        "name": "new_server.new_tool_name",
        "source": "new_server",
        "category": "network",
        "description": "A new registered tool.",
    }, role="admin")
    assert unknown["group_label"] == "MCP"
