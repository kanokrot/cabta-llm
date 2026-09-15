from unittest.mock import patch

import pytest

from src.integrations.threat_feeds import ThreatFeeds
from src.integrations.threat_intel_extended import ThreatIntelExtended


class _FakeResponse:
    def __init__(self, *, status=200, text_data="", json_data=None):
        self.status = status
        self._text_data = text_data
        self._json_data = json_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def text(self):
        return self._text_data

    async def json(self):
        return self._json_data


class _FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    def get(self, url, params=None):
        self.calls.append((url, params))
        return self.responses[url]


@pytest.mark.asyncio
async def test_circl_uses_current_pdns_path_and_parses_ndjson():
    response = _FakeResponse(
        text_data='{"rrtype":"A","rdata":"203.0.113.7"}\n'
        '{"rrtype":"AAAA","rdata":"2001:db8::7"}\n'
    )
    with patch(
        "src.integrations.threat_intel_extended.aiohttp.ClientSession",
        return_value=_FakeSession({
            "https://www.circl.lu/pdns/query/example.org": response
        }),
    ) as client_session:
        result = await ThreatIntelExtended({}).check_circl("example.org")

    assert result["found"] is True
    assert result["records"] == 2
    assert result["status"] == "\u2713"


@pytest.mark.asyncio
async def test_circl_reports_partner_authentication_failure():
    session = _FakeSession({
        "https://www.circl.lu/pdns/query/example.org": _FakeResponse(status=401)
    })
    with patch(
        "src.integrations.threat_intel_extended.aiohttp.ClientSession",
        return_value=session,
    ):
        result = await ThreatIntelExtended({}).check_circl("example.org")

    assert result == {
        "source": "CIRCL",
        "status": "\u26a0",
        "error": "HTTP 401",
        "found": False,
    }


@pytest.mark.asyncio
async def test_sslbl_parses_active_ip_csv_columns_and_certificate_sha1():
    sha1 = "a" * 40
    session = _FakeSession(
        {
            ThreatFeeds.SSLBL_CERT_CSV: _FakeResponse(
                text_data=f"2026-09-15,{sha1},Test C2\n"
            ),
            ThreatFeeds.SSLBL_IP_CSV: _FakeResponse(
                text_data="2026-09-15,203.0.113.7,443\n"
            ),
        }
    )
    feed = ThreatFeeds({})
    with patch.object(feed, "_session", return_value=session):
        cert_result = await feed.check_ssl_blacklist(sha1)
        ip_result = await feed.check_ssl_blacklist("203.0.113.7")

    assert cert_result["found"] is True
    assert ip_result["found"] is True


@pytest.mark.asyncio
async def test_sslbl_does_not_treat_deprecated_ip_feed_as_clean():
    session = _FakeSession(
        {
            ThreatFeeds.SSLBL_CERT_CSV: _FakeResponse(
                text_data=f"2026-09-15,{'b' * 40},Test C2\n"
            ),
            ThreatFeeds.SSLBL_IP_CSV: _FakeResponse(
                text_data="# ATTENTION: This list has been deprecated on 2025-01-03\n"
            ),
        }
    )
    feed = ThreatFeeds({})
    with patch.object(feed, "_session", return_value=session):
        result = await feed.check_ssl_blacklist("203.0.113.7")

    assert result["found"] is False
    assert result["status"] == "\u26a0"
    assert "deprecated" in result["error"]


@pytest.mark.asyncio
async def test_usom_queries_api_and_exact_matches_model_value():
    session = _FakeSession(
        {
            ThreatFeeds.USOM_API_URL: _FakeResponse(
                json_data={
                    "totalCount": 1,
                    "count": 1,
                    "models": [{"url": "evil.example", "type": "domain"}],
                    "page": 0,
                    "pageCount": 1,
                }
            )
        }
    )
    feed = ThreatFeeds({})
    with patch.object(feed, "_session", return_value=session):
        result = await feed.check_usom("EVIL.EXAMPLE")

    assert result["found"] is True
    assert result["message"] == "Found in USOM API"
    assert session.calls == [
        (
            ThreatFeeds.USOM_API_URL,
            {"q": "evil.example", "type": "domain", "per-page": "10"},
        )
    ]


@pytest.mark.asyncio
async def test_usom_rejects_partial_model_match():
    session = _FakeSession(
        {
            ThreatFeeds.USOM_API_URL: _FakeResponse(
                json_data={"models": [{"url": "evil.example/path"}]}
            )
        }
    )
    feed = ThreatFeeds({})
    with patch.object(feed, "_session", return_value=session):
        result = await feed.check_usom("evil.example")

    assert result["found"] is False
    assert result["status"] == "\u2717"
