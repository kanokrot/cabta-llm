from unittest.mock import AsyncMock, Mock

import pytest

from src.integrations.threat_intel import ThreatIntelligence


def _fake_intel(*, threatfox_error=None):
    intel = ThreatIntelligence.__new__(ThreatIntelligence)
    intel._ioc_cache = Mock()
    intel._ioc_cache.get.return_value = None
    intel.check_virustotal = AsyncMock(
        return_value={"status": "clean", "score": 0}
    )
    if threatfox_error is None:
        intel.check_threatfox = AsyncMock(
            return_value={"status": "clean", "score": 0}
        )
    else:
        intel.check_threatfox = AsyncMock(side_effect=threatfox_error)
    return intel


@pytest.mark.asyncio
async def test_progress_callback_runs_once_per_source_with_increasing_done():
    intel = _fake_intel()
    events = []

    await intel.investigate_ioc_comprehensive(
        "1.2.3.4",
        "ipv4",
        allowed_sources={"virustotal", "threatfox"},
        progress_callback=lambda *event: events.append(event),
    )

    assert len(events) == 2
    assert {event[0] for event in events} == {"virustotal", "threatfox"}
    assert {event[1] for event in events} == {"ok"}
    assert sorted(event[2] for event in events) == [1, 2]
    assert {event[3] for event in events} == {2}


@pytest.mark.asyncio
async def test_source_exception_reports_error_and_returns_results():
    intel = _fake_intel(threatfox_error=RuntimeError("source failed"))
    events = []

    result = await intel.investigate_ioc_comprehensive(
        "1.2.3.4",
        "ipv4",
        allowed_sources={"virustotal", "threatfox"},
        progress_callback=lambda *event: events.append(event),
    )

    assert result["sources"]["virustotal"]["status"] == "clean"
    assert result["sources"]["threatfox"]["error"] == "source failed"
    assert {event[0]: event[1] for event in events} == {
        "virustotal": "ok",
        "threatfox": "error",
    }
    assert sorted(event[2] for event in events) == [1, 2]
    assert {event[3] for event in events} == {2}


@pytest.mark.asyncio
async def test_progress_callback_exception_does_not_break_investigation():
    intel = _fake_intel()

    def raising_callback(*_args):
        raise RuntimeError("callback failed")

    result = await intel.investigate_ioc_comprehensive(
        "1.2.3.4",
        "ipv4",
        allowed_sources={"virustotal", "threatfox"},
        progress_callback=raising_callback,
    )

    assert result["sources"]["virustotal"]["status"] == "clean"
    assert result["sources"]["threatfox"]["status"] == "clean"


@pytest.mark.asyncio
async def test_call_without_progress_callback_returns_results():
    intel = _fake_intel()

    result = await intel.investigate_ioc_comprehensive(
        "1.2.3.4",
        "ipv4",
        allowed_sources={"virustotal", "threatfox"},
    )

    assert result["sources"]["virustotal"]["status"] == "clean"
    assert result["sources"]["threatfox"]["status"] == "clean"
    assert result["sources_checked"] == 2
