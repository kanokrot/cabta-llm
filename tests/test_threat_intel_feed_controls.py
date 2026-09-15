import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.integrations.threat_intel import ThreatIntelligence


FIXTURES = Path(__file__).parent / "fixtures"


class _FakeResponse:
    def __init__(self, *, json_data=None, text_data=None, status=200):
        self.status = status
        self._json_data = json_data
        self._text_data = text_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def json(self):
        return self._json_data

    async def text(self):
        return self._text_data


class _FakeSession:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    def get(self, url):
        return self.response


def _intel_with_response(response):
    intel = ThreatIntelligence.__new__(ThreatIntelligence)
    intel.timeout = None
    return intel, patch(
        "src.integrations.threat_intel.aiohttp.ClientSession",
        return_value=_FakeSession(response),
    )


@pytest.mark.asyncio
async def test_feodotracker_fixture_positive_and_negative_controls():
    feed = json.loads((FIXTURES / "feodotracker_ipblocklist.json").read_text(encoding="utf-8"))
    intel, client_patch = _intel_with_response(_FakeResponse(json_data=feed))
    with client_patch:
        positive = await intel.check_feodotracker("198.51.100.10")
        negative = await intel.check_feodotracker("198.51.100.11")

    assert positive["found"] is True
    assert positive["status"] == "✓"
    assert positive["score"] > 0
    assert positive["botnet"] == "TestBot"
    assert negative == {
        "status": "✗",
        "found": False,
        "message": "Not found",
        "score": 0,
    }


@pytest.mark.asyncio
async def test_tor_fixture_uses_exact_line_matching_positive_and_negative_controls():
    feed = (FIXTURES / "torbulkexitlist.txt").read_text(encoding="utf-8")
    intel, client_patch = _intel_with_response(_FakeResponse(text_data=feed))
    with client_patch:
        positive = await intel.check_tor_exit_nodes("198.51.100.10")
        substring_negative = await intel.check_tor_exit_nodes("198.51.100.1")

    assert positive["found"] is True
    assert positive["status"] == "✓"
    assert positive["score"] > 0
    assert substring_negative["found"] is False
    assert substring_negative["status"] == "✗"
    assert substring_negative["score"] == 0
