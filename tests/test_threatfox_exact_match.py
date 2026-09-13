import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.integrations.threat_intel import ThreatIntelligence


def _mock_aiohttp_response(status=200, json_data=None):
    response = AsyncMock()
    response.status = status
    response.json = AsyncMock(return_value=json_data or {})

    response_context = AsyncMock()
    response_context.__aenter__ = AsyncMock(return_value=response)
    response_context.__aexit__ = AsyncMock(return_value=False)
    return response_context


def _mock_session(response_context):
    session = MagicMock()
    session.post = MagicMock(return_value=response_context)

    session_context = AsyncMock()
    session_context.__aenter__ = AsyncMock(return_value=session)
    session_context.__aexit__ = AsyncMock(return_value=False)
    return session_context


def _threatfox_payload(ioc, ioc_type):
    return {
        'query_status': 'ok',
        'data': [
            {
                'ioc': ioc,
                'ioc_type': ioc_type,
                'malware_printable': 'Test malware',
                'malware': 'test_malware',
                'threat_type': 'payload_delivery',
                'confidence_level': 100,
                'first_seen': '2026-01-01 00:00:00 UTC',
            }
        ],
    }


class TestThreatFoxExactMatch(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.threat_intel = ThreatIntelligence({'api_keys': {}})

    async def _check(self, query, returned_ioc, ioc_type):
        response_context = _mock_aiohttp_response(
            json_data=_threatfox_payload(returned_ioc, ioc_type)
        )
        session_context = _mock_session(response_context)
        with patch('src.integrations.threat_intel.aiohttp.ClientSession', return_value=session_context):
            return await self.threat_intel.check_threatfox(query)

    async def test_domain_partial_match_is_not_found(self):
        result = await self._check('amazon.com', 'aqua-amazon.com', 'domain')

        self.assertEqual(result['status'], '✗')
        self.assertFalse(result['found'])
        self.assertEqual(
            result['message'],
            'No exact match (search matched different indicator)',
        )
        self.assertEqual(result['unrelated_match_found'], 'aqua-amazon.com')

    async def test_hosted_url_partial_match_is_not_found(self):
        github_url = (
            'https://github.com/4realgg/Helper-Update1.0/releases/download/'
            'update1/mw--58389c35-c76b-46ac-b33e-7efe83b65fda.zip'
        )
        result = await self._check('github.com', github_url, 'url')

        self.assertEqual(result['status'], '✗')
        self.assertFalse(result['found'])
        self.assertEqual(result['unrelated_match_found'], github_url)

    async def test_exact_domain_match_remains_found(self):
        result = await self._check('evil-c2-server.com', 'evil-c2-server.com', 'domain')

        self.assertEqual(result['status'], '✓')
        self.assertTrue(result['found'])
        self.assertEqual(result['score'], 90)
        self.assertEqual(result['threat_type'], 'payload_delivery')
        self.assertEqual(result['confidence'], 100)

    async def test_exact_url_match_remains_found(self):
        url = 'https://evil.example/payload.exe'
        result = await self._check(url, url, 'url')

        self.assertEqual(result['status'], '✓')
        self.assertTrue(result['found'])
        self.assertEqual(result['score'], 90)


if __name__ == '__main__':
    unittest.main()
