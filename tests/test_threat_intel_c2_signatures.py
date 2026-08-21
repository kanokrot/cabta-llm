"""
Tests for ThreatIntelligence.check_shodan() C2 signature matching.

Covers the fix for a false-positive C2 detection: querying a known-clean IP
(8.8.8.8) triggered a flagged source because C2_SIGNATURES were matched via
raw substring search. The fix (a) removes signatures that are too generic to
ever be safe ('msf', 'Elite', 'grunt', '/images/', 'implant'/'Implant') and
(b) switches matching from substring search to word-boundary regex
(re.escape + \\b where the signature's edge characters are alphanumeric).
"""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.integrations.threat_intel import ThreatIntelligence


def _mock_aiohttp_response(status=200, json_data=None):
    """Create a mock aiohttp response context manager."""
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=json_data or {})

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


def _mock_session(response_ctx):
    """Create a mock aiohttp.ClientSession whose get() returns the given response."""
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=response_ctx)

    session_ctx = AsyncMock()
    session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    session_ctx.__aexit__ = AsyncMock(return_value=False)
    return session_ctx


def _shodan_payload(banner="", html=""):
    return {
        "ports": [80],
        "vulns": [],
        "tags": [],
        "hostnames": [],
        "data": [
            {
                "data": banner,
                "http": {"html": html},
            }
        ],
    }


class TestCheckShodanC2Signatures(unittest.IsolatedAsyncioTestCase):
    """Tests for check_shodan() C2 signature matching after the false-positive fix."""

    def setUp(self):
        config = {"api_keys": {"shodan": "valid_shodan_key_1234567890"}}
        self.ti = ThreatIntelligence(config)

    async def _check(self, banner="", html=""):
        payload = _shodan_payload(banner=banner, html=html)
        resp_ctx = _mock_aiohttp_response(200, payload)
        sess_ctx = _mock_session(resp_ctx)
        with patch("aiohttp.ClientSession", return_value=sess_ctx):
            return await self.ti.check_shodan("8.8.8.8")

    # 2. Genuine whole-word signature -> should still be a true positive.
    async def test_genuine_signature_whole_word_detected(self):
        result = await self._check(banner="PoshC2 beacon detected on this host")
        self.assertTrue(result["is_c2"])
        self.assertIn("poshc2", result["c2_frameworks"])

    # 3. Removed overly generic keywords must never trigger, word boundary or not.
    async def test_removed_generic_keywords_do_not_trigger(self):
        for content in (
            "msf console output",
            "Elite membership program",
            "grunt build tool output",
            "served from /images/logo.png",
        ):
            with self.subTest(content=content):
                result = await self._check(banner=content)
                self.assertFalse(result["is_c2"], f"unexpected C2 flag for: {content!r}")
                self.assertEqual(result["c2_frameworks"], [])

    # 4. Signature containing regex special characters must still match via re.escape().
    async def test_special_character_signature_still_matches(self):
        result = await self._check(html="<a href='/admin/get.php'>login</a>")
        self.assertTrue(result["is_c2"])
        self.assertIn("empire", result["c2_frameworks"])

    async def test_special_character_signature_shellcode_marker(self):
        result = await self._check(banner="beacon stage: %c%c%c%c%c%c%c%c%cMSSE detected")
        self.assertTrue(result["is_c2"])
        self.assertIn("cobalt_strike", result["c2_frameworks"])

    # 'implant'/'Implant' were dropped entirely from poshc2/sliver (extended
    # Part A scope): live evidence showed it has the same false-positive
    # pattern as 'msf'/'Elite'/'grunt' -- a whole-word but benign occurrence
    # (e.g. "dental implant services") is indistinguishable from a real C2
    # hit, so no amount of word-boundary matching alone can save it.
    async def test_implant_substring_inside_longer_word_not_flagged(self):
        result = await self._check(banner="breast implantation surgery recovery information")
        self.assertFalse(result["is_c2"])
        self.assertEqual(result["c2_frameworks"], [])

    # 1. Requested scenario: 'implant' as a genuine whole word in benign content.
    async def test_implant_whole_word_in_benign_context_not_flagged(self):
        result = await self._check(banner="dental implant services available now")
        self.assertFalse(result["is_c2"])
        self.assertEqual(result["c2_frameworks"], [])


if __name__ == "__main__":
    unittest.main()
