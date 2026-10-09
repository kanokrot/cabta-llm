import socket
from unittest.mock import patch

import pytest

from src.integrations.threat_intel_extended import ThreatIntelExtended


@pytest.mark.asyncio
async def test_spamhaus_nxdomain_is_clean():
    with patch(
        "socket.gethostbyname",
        side_effect=socket.gaierror(socket.EAI_NONAME, "name not found"),
    ):
        result = await ThreatIntelExtended({}).check_spamhaus("198.51.100.9")

    assert result["status"] == "\u2717"
    assert result["found"] is False
    assert result["listed"] is False


@pytest.mark.asyncio
async def test_spamhaus_resolver_error_is_unavailable():
    with patch(
        "socket.gethostbyname",
        side_effect=socket.gaierror(socket.EAI_AGAIN, "temporary failure"),
    ):
        result = await ThreatIntelExtended({}).check_spamhaus("198.51.100.9")

    assert result["status"] == "\u26a0"
    assert result["found"] is False
    assert result["unavailable"] is True
    assert "resolver error" in result["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", ["127.0.0.2", "127.0.0.11"])
async def test_spamhaus_documented_listing_codes_are_listings(answer):
    with patch("socket.gethostbyname", return_value=answer):
        result = await ThreatIntelExtended({}).check_spamhaus("198.51.100.9")

    assert result["status"] == "\u2713"
    assert result["found"] is True
    assert result["listed"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    ["127.0.0.1", "127.0.0.12", "127.255.255.1", "127.255.255.252", "127.255.255.254", "127.255.255.255", "8.8.8.8"],
)
async def test_spamhaus_non_listing_answer_is_unavailable(answer):
    with patch("socket.gethostbyname", return_value=answer):
        result = await ThreatIntelExtended({}).check_spamhaus("198.51.100.9")

    assert result["status"] == "\u26a0"
    assert result["found"] is False
    assert result["unavailable"] is True
    assert answer in result["error"]
