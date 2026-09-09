"""Tests for the search_threat_intel source parameter."""

import pytest

from src.agent.tool_registry import ToolRegistry


class SpyIOCInvestigator:
    def __init__(self):
        self.calls = []

    async def investigate(self, ioc, analysis_id=None):
        self.calls.append({"ioc": ioc, "analysis_id": analysis_id})
        return {"status": "success", "ioc": ioc}


@pytest.fixture
def search_tool():
    investigator = SpyIOCInvestigator()
    registry = ToolRegistry()
    registry.register_default_tools(config={}, ioc_investigator=investigator)
    return registry, investigator


@pytest.mark.asyncio
async def test_non_all_source_returns_clear_unsupported_error(search_tool):
    registry, investigator = search_tool

    result = await registry.execute_local_tool(
        "search_threat_intel", query="192.0.2.10", source="virustotal"
    )

    assert result == {
        "error": (
            "source filtering is not yet supported; 'virustotal' was requested but "
            "investigate() searches all configured sources. Use source='all' or omit "
            "this parameter."
        )
    }
    assert investigator.calls == []


@pytest.mark.asyncio
async def test_all_source_still_runs_investigation(search_tool):
    registry, investigator = search_tool

    result = await registry.execute_local_tool(
        "search_threat_intel", query="192.0.2.10", source="all"
    )

    assert result == {"status": "success", "ioc": "192.0.2.10"}
    assert investigator.calls == [{"ioc": "192.0.2.10", "analysis_id": None}]
