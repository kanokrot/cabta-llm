"""Regression coverage for block_ip single and batched indicator inputs."""

import pytest

from src.agent import tool_registry as tool_registry_module
from src.agent.tool_registry import ToolRegistry


@pytest.fixture
def tool_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_registry_module, "_SIMULATED_ACTIONS_DIR", tmp_path)
    registry = ToolRegistry()
    registry.register_default_tools({})
    return registry


@pytest.mark.asyncio
async def test_single_ip_address_backward_compat(tool_registry):
    result = await tool_registry.execute_local_tool(
        "block_ip", ip_address="1.2.3.4"
    )

    assert "error" not in result
    assert result["record"]["ip_address"] == "1.2.3.4"
    assert "1 indicator(s)" in result["message"]


@pytest.mark.asyncio
async def test_indicators_list_batches_all(tool_registry):
    result = await tool_registry.execute_local_tool(
        "block_ip", indicators=["1.2.3.4", "5.6.7.8"]
    )

    assert "error" not in result
    assert isinstance(result["record"], list)
    assert len(result["record"]) == 2
    assert [record["ip_address"] for record in result["record"]] == [
        "1.2.3.4",
        "5.6.7.8",
    ]
    assert "2 indicator(s)" in result["message"]


@pytest.mark.asyncio
async def test_single_item_indicators_list_returns_single_record_not_list(tool_registry):
    result = await tool_registry.execute_local_tool(
        "block_ip", indicators=["1.2.3.4"]
    )

    assert "error" not in result
    assert isinstance(result["record"], dict)
    assert result["record"]["ip_address"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_empty_indicators_list_returns_error(tool_registry):
    result = await tool_registry.execute_local_tool("block_ip", indicators=[])

    assert "error" in result or result.get("status") == "error"


@pytest.mark.asyncio
async def test_both_unset_returns_error(tool_registry):
    result = await tool_registry.execute_local_tool("block_ip")

    assert "error" in result or result.get("status") == "error"


@pytest.mark.asyncio
async def test_indicators_filters_out_blank_strings(tool_registry):
    result = await tool_registry.execute_local_tool(
        "block_ip", indicators=["1.2.3.4", "", "5.6.7.8"]
    )

    assert "error" not in result
    assert isinstance(result["record"], list)
    assert [record["ip_address"] for record in result["record"]] == [
        "1.2.3.4",
        "5.6.7.8",
    ]
    assert "2 indicator(s)" in result["message"]


@pytest.mark.asyncio
async def test_indicators_takes_precedence_when_both_provided(tool_registry):
    result = await tool_registry.execute_local_tool(
        "block_ip",
        ip_address="9.9.9.9",
        indicators=["1.2.3.4", "5.6.7.8"],
    )

    assert "error" not in result
    assert isinstance(result["record"], list)
    assert [record["ip_address"] for record in result["record"]] == [
        "1.2.3.4",
        "5.6.7.8",
    ]
    assert all(record["ip_address"] != "9.9.9.9" for record in result["record"])
