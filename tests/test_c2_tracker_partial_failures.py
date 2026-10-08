import asyncio
from unittest.mock import patch

import pytest

from src.integrations.threat_intel import ThreatIntelligence


class _Response:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def text(self):
        return "198.51.100.7, cobalt_strike, 2026-01-01"


class _Session:
    def __init__(self, *, fail_first):
        self.fail_first = fail_first
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    def get(self, url):
        self.calls += 1
        if self.fail_first and self.calls == 1:
            raise asyncio.TimeoutError()
        return _Response()


@pytest.mark.asyncio
@pytest.mark.parametrize("ioc", ["198.51.100.7"])
async def test_c2_hit_from_working_feed_survives_another_feed_failure(ioc):
    session = _Session(fail_first=True)
    intel = ThreatIntelligence.__new__(ThreatIntelligence)

    with patch(
        "src.integrations.threat_intel.aiohttp.ClientSession",
        return_value=session,
    ):
        result = await intel.check_c2_trackers(ioc)

    assert result["found"] is True
    assert result["status"] == "✓"
    assert result["score"] > 0
    assert result["sources_failed"] == 1
    assert "unavailable" not in result


@pytest.mark.asyncio
async def test_c2_no_hit_with_failed_feed_is_unavailable_and_names_count():
    class _NoHitResponse(_Response):
        async def text(self):
            return "no matching indicators"

    class _NoHitSession(_Session):
        def get(self, url):
            self.calls += 1
            if self.calls == 1:
                raise asyncio.TimeoutError()
            return _NoHitResponse()

    session = _NoHitSession(fail_first=True)
    intel = ThreatIntelligence.__new__(ThreatIntelligence)

    with patch(
        "src.integrations.threat_intel.aiohttp.ClientSession",
        return_value=session,
    ):
        result = await intel.check_c2_trackers("198.51.100.8")

    assert result["found"] is False
    assert result["status"] == "⚠"
    assert result["score"] == 0
    assert result["unavailable"] is True
    assert result["sources_failed"] == 1
    assert "1 C2 tracker feed" in result["error"]
