"""Coverage for Suricata and firewall outputs from generate_rules."""

import pytest

from src.agent.tool_registry import ToolRegistry


@pytest.fixture
def tool_registry():
    registry = ToolRegistry()
    registry.register_default_tools({})
    return registry


def _capa_envelope():
    return {
        "result": {
            "file": "sample.exe",
            "capabilities": [
                {
                    "name": "inject into process",
                    "namespace": "host-interaction/process/inject",
                    "scope": "function",
                }
            ],
            "mitre_attacks": [
                {
                    "technique": "Process Injection",
                    "id": "T1055",
                    "tactic": "Defense Evasion",
                }
            ],
        },
        "server": "flare",
        "tool": "capa_analyze",
    }


@pytest.mark.asyncio
async def test_ioc_shape_produces_suricata_and_firewall(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"ioc": "203.0.113.42", "ioc_type": "ipv4"},
    )

    assert "alert ip" in result["rules"]["suricata"]
    assert "203.0.113.42" in result["rules"]["suricata"]
    assert "action=deny" in result["rules"]["firewall"]
    assert "203.0.113.42" in result["rules"]["firewall"]


@pytest.mark.asyncio
async def test_aggregate_shape_produces_suricata_and_firewall(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={
            "ipv4": ["203.0.113.42"],
            "domains": ["malicious.example"],
            "urls": ["https://malicious.example/payload"],
            "sha256": [],
        },
    )

    assert len(result["rules"]["suricata"]) == 3
    assert len(result["rules"]["firewall"]) == 3
    assert any("alert dns" in rule for rule in result["rules"]["suricata"])
    assert any("indicator_type=url" in rule for rule in result["rules"]["firewall"])


@pytest.mark.asyncio
async def test_capa_shape_with_network_iocs_produces_suricata_firewall(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result=_capa_envelope(),
        network_iocs=[
            "203.0.113.42",
            {"value": "malicious.example", "type": "domain"},
            {"ioc": "https://malicious.example/payload", "ioc_type": "url"},
        ],
    )

    assert result["rules"]["yara"]
    assert result["rules"]["sigma"]
    assert len(result["rules"]["suricata"]) == 3
    assert len(result["rules"]["firewall"]) == 3


@pytest.mark.asyncio
async def test_capa_shape_accepts_extract_iocs_wrapper(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result=_capa_envelope(),
        network_iocs={
            "iocs": {
                "ipv4": ["203.0.113.42"],
                "domains": ["malicious.example"],
                "urls": ["https://malicious.example/payload"],
                "emails": [],
                "hashes": {},
            }
        },
    )

    assert len(result["rules"]["suricata"]) == 3
    assert len(result["rules"]["firewall"]) == 3


@pytest.mark.asyncio
async def test_capa_shape_without_network_iocs_unchanged(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules", analysis_result=_capa_envelope()
    )

    assert set(result["rules"]) == {"yara", "sigma"}
    assert len(result["rules"]["yara"]) == 1
    assert len(result["rules"]["sigma"]) == 1


@pytest.mark.asyncio
async def test_snort_alias_filters_to_suricata(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"ioc": "203.0.113.42", "ioc_type": "ipv4"},
        rule_types=["snort"],
    )

    assert set(result["rules"]) == {"suricata"}


@pytest.mark.asyncio
async def test_rule_types_plural_with_suricata_firewall(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"ioc": "malicious.example", "ioc_type": "domain"},
        rule_types=["suricata", "firewall"],
    )

    assert set(result["rules"]) == {"suricata", "firewall"}
