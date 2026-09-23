import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.integrations.threat_intel import ThreatIntelligence


def _build_intel(alienvault_result, cached_result=None):
    intel = ThreatIntelligence.__new__(ThreatIntelligence)
    intel._ioc_cache = Mock()
    intel._ioc_cache.get.return_value = cached_result

    intel.check_virustotal = AsyncMock(
        return_value={"status": "⚠", "error": "No valid API key configured"}
    )
    intel.check_threatfox = AsyncMock(
        return_value={"status": "✗", "found": False, "score": 0}
    )
    if isinstance(alienvault_result, BaseException):
        intel.check_alienvault = AsyncMock(side_effect=alienvault_result)
    else:
        intel.check_alienvault = AsyncMock(return_value=alienvault_result)
    intel.check_c2_trackers = AsyncMock(
        return_value={"status": "✗", "found": False, "score": 0}
    )
    intel.extended = SimpleNamespace(
        check_pulsedive=AsyncMock(
            return_value={"status": "⚠", "error": "No valid API key configured"}
        ),
        check_circl=AsyncMock(return_value={"status": "✗", "found": False}),
    )
    intel.threat_feeds = SimpleNamespace(
        check_smet_nrd=AsyncMock(
            return_value={"status": "\u2717", "found": False, "score": 0}
        ),
        check_hagezi_nrd=AsyncMock(
            return_value={"status": "\u2717", "found": False, "score": 0}
        ),
    )
    intel.misp_feed = SimpleNamespace(
        check_misp=AsyncMock(
            return_value={
                "status": "✗",
                "found": False,
                "score": 0,
                "feed_status": "unavailable",
            }
        ),
    )
    return intel


@pytest.mark.asyncio
async def test_successful_source_result_is_cached():
    live_result = {"status": "✓", "pulses": 21, "score": 100}
    intel = _build_intel(live_result)

    result = await intel.investigate_ioc_comprehensive("evil.com", "domain")

    assert result["sources"]["alienvault"] == live_result
    intel._ioc_cache.set.assert_any_call(
        "evil.com", "domain", "alienvault", live_result
    )
    assert "cached" not in result["sources"]["alienvault"]


@pytest.mark.asyncio
async def test_timeout_uses_unexpired_cached_source_result():
    cached_result = {"status": "✓", "pulses": 21, "score": 100}
    intel = _build_intel(asyncio.TimeoutError(), cached_result)

    result = await intel.investigate_ioc_comprehensive("evil.com", "domain")

    assert result["sources"]["alienvault"] == {
        **cached_result,
        "cached": True,
        "cache_reason": "timeout",
    }
    intel._ioc_cache.get.assert_called_once_with(
        "evil.com", "domain", "alienvault"
    )


@pytest.mark.asyncio
async def test_timeout_without_cache_preserves_error_result():
    intel = _build_intel(asyncio.TimeoutError(), None)

    result = await intel.investigate_ioc_comprehensive("evil.com", "domain")

    assert result["sources"]["alienvault"] == {
        "status": "⚠",
        "error": "Timeout",
        "cached": False,
    }


@pytest.mark.asyncio
async def test_threatfox_timeout_is_unavailable_without_cache_fallback():
    intel = _build_intel(None)
    intel.check_threatfox = AsyncMock(side_effect=asyncio.TimeoutError())

    result = await intel.investigate_ioc_comprehensive(
        "evil.com", "domain", allowed_sources={"threatfox"}
    )

    assert result["sources"]["threatfox"] == {
        "status": "⚠",
        "error": "Timeout after 15s",
        "found": False,
        "score": 0,
        "unavailable": True,
        "timeout": True,
        "cached": False,
    }
    # ThreatFox timeout handling must not read or use stale cache data.
    intel._ioc_cache.get.assert_not_called()


@pytest.mark.asyncio
async def test_threatfox_timeout_does_not_dilute_aggregate_score():
    intel = _build_intel(None)
    intel.check_threatfox = AsyncMock(side_effect=asyncio.TimeoutError())
    intel.check_c2_trackers = AsyncMock(
        return_value={"status": "ok", "found": True, "score": 100}
    )

    result = await intel.investigate_ioc_comprehensive(
        "evil.com", "domain", allowed_sources={"threatfox", "c2_trackers"}
    )

    assert result["threat_score"] == 100


@pytest.mark.asyncio
async def test_source_error_uses_unexpired_cached_source_result():
    cached_result = {"status": "✓", "pulses": 21, "score": 100}
    intel = _build_intel(RuntimeError("upstream unavailable"), cached_result)

    result = await intel.investigate_ioc_comprehensive("evil.com", "domain")

    assert result["sources"]["alienvault"] == {
        **cached_result,
        "cached": True,
        "cache_reason": "error",
    }
    intel._ioc_cache.get.assert_called_once_with(
        "evil.com", "domain", "alienvault"
    )
