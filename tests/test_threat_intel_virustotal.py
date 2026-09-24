from unittest.mock import patch

import pytest

from src.integrations.threat_intel import ThreatIntelligence, _vt_url_id


SAMPLE_URL = "https://example.com/path?q=1"
SAMPLE_URL_ID = "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRoP3E9MQ"


class _FakeResponse:
    def __init__(self, payload, status=200):
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def json(self):
        return self.payload


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    def get(self, url, headers=None):
        self.calls.append((url, headers))
        return self.response


def _intel_and_session(payload):
    intel = ThreatIntelligence.__new__(ThreatIntelligence)
    intel.api_keys = {"virustotal": "valid-vt-key-0000000000"}
    intel.timeout = None
    session = _FakeSession(_FakeResponse(payload))
    return intel, session


@pytest.mark.asyncio
async def test_vt_url_id_encoding_matches_existing_production_behavior():
    assert _vt_url_id(SAMPLE_URL) == SAMPLE_URL_ID


@pytest.mark.asyncio
async def test_get_raw_virustotal_report_url_uses_urls_endpoint_without_relationships():
    payload = {"data": {"type": "url", "id": SAMPLE_URL_ID}}
    intel, session = _intel_and_session(payload)

    with patch("src.integrations.threat_intel.aiohttp.ClientSession", return_value=session):
        result = await intel.get_raw_virustotal_report(SAMPLE_URL, "url")

    assert result == payload
    assert session.calls[0][0] == (
        f"https://www.virustotal.com/api/v3/urls/{SAMPLE_URL_ID}"
    )
    assert "relationships" not in session.calls[0][0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ioc", "ioc_type", "expected_endpoint"),
    [
        (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "hash",
            "files/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        (
            "8.8.8.8",
            "ipv4",
            "ip_addresses/8.8.8.8?relationships=communicating_files,downloaded_files,resolutions",
        ),
        (
            "example.com",
            "domain",
            "domains/example.com",
        ),
    ],
)
async def test_get_raw_virustotal_report_existing_types_keep_endpoints(
    ioc, ioc_type, expected_endpoint
):
    payload = {"data": {"type": ioc_type, "id": ioc}}
    intel, session = _intel_and_session(payload)

    with patch("src.integrations.threat_intel.aiohttp.ClientSession", return_value=session):
        result = await intel.get_raw_virustotal_report(ioc, ioc_type)

    assert result == payload
    assert session.calls[0][0] == (
        f"https://www.virustotal.com/api/v3/{expected_endpoint}"
    )


@pytest.mark.asyncio
async def test_check_virustotal_url_still_uses_same_url_id_after_helper_extraction():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 1, "harmless": 1},
            }
        }
    }
    intel, session = _intel_and_session(payload)

    with patch("src.integrations.threat_intel.aiohttp.ClientSession", return_value=session):
        result = await intel.check_virustotal(SAMPLE_URL, "url")

    assert result["detections"] == "1/2"
    assert session.calls[0][0] == (
        f"https://www.virustotal.com/api/v3/urls/{SAMPLE_URL_ID}"
    )
