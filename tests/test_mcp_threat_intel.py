"""
Regression + integration tests for URLhaus lookup and the
threat_intel_tools MCP server.

Context (2026-08-30 debugging session):
    1) urlhaus_lookup() sent form-urlencoded body but reused JSON
       Content-Type headers -> fixed (see git history).
    2) First version of this test file split connect()/call_tool()/
       disconnect() across separate asyncio.run() calls (fixture setup,
       test body, teardown), each spinning up its own event loop. The
       MCP stdio client's background reader task is bound to the loop
       it was created in, so call_tool() run in a different loop never
       saw a response -> hung until the internal 60s wait_for() timeout.
       Fixed by keeping connect/call/disconnect on a single event loop
       via async fixtures + async test functions (pytest-asyncio).
"""
import json
import sys
import time
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.mcp_servers.threat_intel_tools import urlhaus_lookup, _threatfox_headers
from src.agent.mcp_client import MCPClientManager, MCPServerConfig


def _has_abusech_key() -> bool:
    return "Auth-Key" in _threatfox_headers()


requires_abusech_key = pytest.mark.skipif(
    not _has_abusech_key(),
    reason="No abuse.ch Auth-Key configured in config.yaml (api_keys.threatfox / api_keys.abusech)",
)


@requires_abusech_key
def test_urlhaus_lookup_direct_call_returns_valid_json():
    """urlhaus_lookup() must return parseable JSON with no 'error' key."""
    raw = urlhaus_lookup("1.1.1.1")
    result = json.loads(raw)

    assert "error" not in result, f"urlhaus_lookup failed: {result}"
    assert "query_status" in result, f"unexpected response shape: {result}"


@pytest_asyncio.fixture
async def mcp_manager():
    """
    Async fixture: setup, test body, and teardown all share ONE event
    loop (managed by pytest-asyncio), matching the working adhoc scripts.
    """
    mgr = MCPClientManager()
    cfg = MCPServerConfig(
        name="threat_intel_tools",
        transport="stdio",
        command="python",
        args=["-m", "src.mcp_servers.threat_intel_tools"],
        env=None,
    )

    connected = await mgr.connect(cfg)
    assert connected, "threat_intel_tools MCP server failed to connect"

    yield mgr

    await mgr.disconnect("threat_intel_tools")


@pytest.mark.asyncio
async def test_mcp_server_connects(mcp_manager):
    """If this test runs at all, the fixture's connect() already succeeded."""
    assert mcp_manager is not None


@requires_abusech_key
@pytest.mark.asyncio
async def test_mcp_call_tool_urlhaus_lookup_works(mcp_manager):
    """
    End-to-end: call urlhaus_lookup through the real MCP stdio transport,
    exactly as the agent loop would, and check the result is usable.
    """
    response = await mcp_manager.call_tool(
        "threat_intel_tools", "urlhaus_lookup", {"indicator": "9.9.9.9"}
    )
    result = response.get("result", response)

    assert "error" not in result, f"MCP call_tool returned an error: {result}"
    assert "query_status" in result, f"unexpected response shape: {result}"


@requires_abusech_key
@pytest.mark.asyncio
async def test_mcp_call_tool_response_time_is_reasonable(mcp_manager):
    """
    Regression guard: this call should complete in a few seconds over
    stdio MCP transport. If it starts taking ~60s again, something in
    the transport or handler has regressed.
    """
    start = time.time()
    await mcp_manager.call_tool(
        "threat_intel_tools", "urlhaus_lookup", {"indicator": "8.8.4.4"}
    )
    elapsed = time.time() - start

    assert elapsed < 10, f"urlhaus_lookup took {elapsed:.2f}s over MCP - expected under 10s"
