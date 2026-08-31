"""Regression coverage for capa analysis-result rule generation."""

import re

import pytest

from src.agent.tool_registry import ToolRegistry


@pytest.fixture
def tool_registry():
    registry = ToolRegistry()
    registry.register_default_tools({})
    return registry


def _capa_summary():
    return {
        "file": "test.exe",
        "matched_rules": 2,
        "capabilities": [
            {
                "name": "inject into process",
                "namespace": "host-interaction/process/inject",
                "scope": "function",
            },
            {
                "name": "encrypt data via WinCrypt",
                "namespace": "data-manipulation/encryption",
                "scope": "function",
            },
        ],
        "mitre_attacks": [
            {
                "technique": "Process Injection",
                "id": "T1055",
                "tactic": "Defense Evasion",
            },
        ],
    }


def _assert_two_yara_one_sigma(result):
    assert "error" not in result
    assert isinstance(result["rules"]["yara"], list)
    assert len(result["rules"]["yara"]) == 2
    assert isinstance(result["rules"]["sigma"], list)
    assert len(result["rules"]["sigma"]) == 1
    assert "attack.t1055" in result["rules"]["sigma"][0]


@pytest.mark.asyncio
async def test_envelope_shape_produces_yara_and_sigma(tool_registry):
    analysis_result = {
        "result": _capa_summary(),
        "server": "flare",
        "tool": "capa_analyze",
    }

    result = await tool_registry.execute_local_tool(
        "generate_rules", analysis_result=analysis_result
    )

    _assert_two_yara_one_sigma(result)


@pytest.mark.asyncio
async def test_unwrapped_shape_produces_yara_and_sigma(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules", analysis_result=_capa_summary()
    )

    _assert_two_yara_one_sigma(result)


@pytest.mark.asyncio
async def test_all_empty_returns_clean_error(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"capabilities": [], "mitre_attacks": []},
    )

    assert result == {
        "error": "No capa capabilities or MITRE techniques found in analysis_result."
    }


@pytest.mark.asyncio
async def test_yara_rule_count_matches_capabilities_count(tool_registry):
    capabilities = [
        {"name": f"capability {index}", "namespace": "test", "scope": "function"}
        for index in range(3)
    ]
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"capabilities": capabilities, "mitre_attacks": []},
    )

    assert "error" not in result
    assert isinstance(result["rules"]["yara"], list)
    assert len(result["rules"]["yara"]) == 3
    assert not result["rules"].get("sigma")


@pytest.mark.asyncio
async def test_yara_identifier_sanitization(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={
            "capabilities": [
                {
                    "name": "123 inject/into process",
                    "namespace": "host-interaction/process/inject",
                    "scope": "function",
                }
            ],
            "mitre_attacks": [],
        },
    )

    assert "error" not in result
    rule_text = result["rules"]["yara"][0]
    identifier_match = re.search(r"^rule ([A-Za-z_][A-Za-z0-9_]*) \{$", rule_text, re.MULTILINE)
    assert identifier_match is not None


@pytest.mark.asyncio
async def test_sigma_rule_count_matches_mitre_attacks_count(tool_registry):
    mitre_attacks = [
        {
            "technique": "Process Injection",
            "id": "T1055",
            "tactic": "Defense Evasion",
        },
        {
            "technique": "Data Encrypted for Impact",
            "id": "T1486",
            "tactic": "Impact",
        },
    ]
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"capabilities": [], "mitre_attacks": mitre_attacks},
    )

    assert "error" not in result
    assert not result["rules"].get("yara")
    assert isinstance(result["rules"]["sigma"], list)
    assert len(result["rules"]["sigma"]) == 2


@pytest.mark.asyncio
async def test_capa_shape_does_not_collide_with_file_shape(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={
            "hashes": {
                "sha256": "a" * 64,
                "md5": "b" * 32,
            },
            "capabilities": [
                {
                    "name": "inject into process",
                    "namespace": "host-interaction/process/inject",
                    "scope": "function",
                }
            ],
            "mitre_attacks": [],
        },
    )

    assert "error" not in result
    assert isinstance(result["rules"]["yara"], list)

