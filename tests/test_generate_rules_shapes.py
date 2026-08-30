"""Regression coverage for generate_rules analysis-result shape handling."""

import pytest

from src.agent.tool_registry import ToolRegistry


@pytest.fixture
def tool_registry():
    registry = ToolRegistry()
    registry.register_default_tools({})
    return registry


def _file_analysis_result():
    return {
        "filename": "sample.exe",
        "hashes": {
            "sha256": (
                "abcdef0123456789abcdef0123456789"
                "abcdef0123456789abcdef0123456789"
            ),
            "md5": "0123456789abcdef0123456789abcdef",
        },
    }


@pytest.mark.asyncio
async def test_aggregate_shape_with_real_iocs(tool_registry):
    iocs = {
        "ipv4": ["203.0.113.42"],
        "domains": ["malicious-example.test"],
        "urls": ["https://malicious-example.test/payload"],
        "sha256": [
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        ],
    }

    result = await tool_registry.execute_local_tool(
        "generate_rules", analysis_result=iocs
    )

    assert "error" not in result
    assert isinstance(result["rules"]["kql"], list)
    assert len(result["rules"]["kql"]) == sum(len(values) for values in iocs.values())
    combined_kql = "\n".join(result["rules"]["kql"])
    assert "203.0.113.42" in combined_kql
    assert "malicious-example.test" in combined_kql
    assert "https://malicious-example.test/payload" in combined_kql


@pytest.mark.asyncio
async def test_aggregate_shape_all_empty(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"ipv4": [], "domains": [], "urls": [], "sha256": []},
    )

    assert result == {
        "error": (
            "No IOCs found in aggregate analysis_result "
            "(ipv4/domains/urls/sha256 were all empty)."
        )
    }


@pytest.mark.asyncio
async def test_non_dict_analysis_result(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules", analysis_result="not a dict"
    )

    assert "must be an object/dict" in result["error"]
    assert "str" in result["error"]


@pytest.mark.asyncio
async def test_rule_types_plural_filters_correctly(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result=_file_analysis_result(),
        rule_types=["yara", "sigma"],
    )

    assert set(result["rules"]) == {"yara", "sigma"}
    assert "kql" not in result["rules"]
    assert "spl" not in result["rules"]


@pytest.mark.asyncio
async def test_rule_types_takes_precedence_over_rule_type(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result=_file_analysis_result(),
        rule_type="kql",
        rule_types=["yara"],
    )

    assert set(result["rules"]) == {"yara"}


@pytest.mark.asyncio
async def test_rule_types_all_unsupported_returns_error(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result=_file_analysis_result(),
        rule_types=["nonexistent_format"],
    )

    assert "error" in result
    assert "nonexistent_format" in result["error"]
    assert "Available:" in result["error"]


@pytest.mark.asyncio
async def test_sha256_list_no_longer_misroutes_to_file_branch(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={
            "sha256": ["abc123def456"],
            "ipv4": [],
            "domains": [],
            "urls": [],
        },
    )

    assert "error" not in result
    assert "rules" in result
    assert isinstance(result["rules"]["kql"], list)
    assert len(result["rules"]["kql"]) == 1


@pytest.mark.asyncio
async def test_legacy_ioc_shape_still_works(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules",
        analysis_result={"ioc": "1.2.3.4", "ioc_type": "ipv4"},
    )

    assert "error" not in result
    assert "rules" in result
    assert result["rules"]


@pytest.mark.asyncio
async def test_legacy_email_shape_still_works(tool_registry):
    result = await tool_registry.execute_local_tool(
        "generate_rules", analysis_result={"subject": "test"}
    )

    assert "error" not in result
    assert {
        "fortimail",
        "proofpoint",
        "mimecast",
        "microsoft365",
    }.issubset(result["rules"])
