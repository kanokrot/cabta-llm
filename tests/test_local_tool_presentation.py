"""Regression tests for built-in local tool presentation metadata."""

import re
from pathlib import Path

from src.agent.local_tool_presentation import (
    LOCAL_TOOL_PRESENTATION,
)
from src.agent.tool_registry import ToolRegistry
from src.web.visibility import serialize_tool_definition


EXPECTED_LOCAL_TOOLS = {
    "investigate_ioc": ("IOC Investigation", "threat-intel"),
    "analyze_malware": ("Malware Analysis", "malware"),
    "analyze_email": ("Email Analysis", "malware"),
    "extract_iocs": ("IOC Extractor", "threat-intel"),
    "generate_rules": ("Rule Generator", "malware"),
    "yara_scan": ("YARA Scanner", "malware"),
    "search_threat_intel": ("Threat Intel Search", "threat-intel"),
    "sandbox_submit": ("Sandbox Submit", "malware"),
    "correlate_findings": ("MITRE Correlation", "malware"),
    "recall_ioc": ("IOC Recall", "threat-intel"),
    "isolate_device": ("Device Isolation", "malware"),
    "block_ip": ("IP Block", "network"),
    "extract_file_hash_pairs": ("File Hash Pairs", "forensics"),
    "quarantine_file": ("File Quarantine", "malware"),
}


def test_local_presentation_has_exactly_14_unique_names_and_valid_icons():
    icon_source = Path("static/img/mcp-tool-icons.svg").read_text(encoding="utf-8")
    valid_icons = set(re.findall(r'<symbol id="([^"]+)"', icon_source))

    assert set(LOCAL_TOOL_PRESENTATION) == set(EXPECTED_LOCAL_TOOLS)
    assert len({item.display_name for item in LOCAL_TOOL_PRESENTATION.values()}) == 14

    for name, (display_name, icon) in EXPECTED_LOCAL_TOOLS.items():
        item = LOCAL_TOOL_PRESENTATION[name]
        assert (item.display_name, item.icon) == (display_name, icon)
        assert 1 <= len(item.display_name.split()) <= 3
        assert item.icon in valid_icons


def test_local_presentation_serialization_preserves_technical_names():
    registry = ToolRegistry()
    dependency = object()
    registry.register_default_tools(
        {},
        ioc_investigator=dependency,
        malware_analyzer=dependency,
        email_analyzer=dependency,
    )

    serialized = [
        serialize_tool_definition(tool, role="admin")
        for tool in registry.list_tools()
    ]
    by_name = {item["name"]: item for item in serialized if item is not None}

    assert set(by_name) == set(EXPECTED_LOCAL_TOOLS)
    for technical_name, (display_name, icon) in EXPECTED_LOCAL_TOOLS.items():
        assert by_name[technical_name]["name"] == technical_name
        assert by_name[technical_name]["display_name"] == display_name
        assert by_name[technical_name]["icon"] == icon


def test_unmapped_local_tool_keeps_the_existing_fallback():
    serialized = serialize_tool_definition(
        {
            "name": "new_local_tool",
            "description": "A new local tool.",
            "source": "local",
            "category": "analysis",
        },
        role="admin",
    )

    assert serialized["name"] == "new_local_tool"
    assert serialized["display_name"] == "New Local Tool"
    assert serialized["icon"] == "malware"
    assert serialized["summary"] == "A new local tool."
