"""Regression tests for the Censys Platform API integration."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.threat_intel_extended import ThreatIntelExtended


VALID_CENSYS_PAT = "censys_pat_1234567890"


def _mock_client_session(response_data):
    response = AsyncMock()
    response.status = 200
    response.json = AsyncMock(return_value=response_data)

    response_context = AsyncMock()
    response_context.__aenter__ = AsyncMock(return_value=response)
    response_context.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=response_context)

    session_context = AsyncMock()
    session_context.__aenter__ = AsyncMock(return_value=session)
    session_context.__aexit__ = AsyncMock(return_value=False)
    return session, session_context


@pytest.mark.asyncio
async def test_check_censys_platform_response_and_bearer_auth():
    client = ThreatIntelExtended({'api_keys': {'censys': VALID_CENSYS_PAT}})
    response_data = {
        'result': {
            'resource': {
                'services': [{}, {}, {}],
                'location': {'country': 'US'},
                'autonomous_system': {'name': 'EXAMPLE-AS'},
            }
        }
    }
    session, session_context = _mock_client_session(response_data)

    with patch(
        'src.integrations.threat_intel_extended.aiohttp.ClientSession',
        return_value=session_context,
    ):
        result = await client.check_censys('203.0.113.10', 'ipv4')

    assert result == {
        'source': 'Censys',
        'found': True,
        'services': 3,
        'location': 'US',
        'autonomous_system': 'EXAMPLE-AS',
        'status': '✓',
    }
    session.get.assert_called_once()
    request_url = session.get.call_args.args[0]
    request_kwargs = session.get.call_args.kwargs
    assert request_url == (
        'https://api.platform.censys.io/v3/global/asset/host/203.0.113.10'
    )
    assert 'api.platform.censys.io/v3/global/asset/host/' in request_url
    assert request_kwargs['headers'] == {
        'Authorization': f'Bearer {VALID_CENSYS_PAT}'
    }
    assert 'auth' not in request_kwargs


@pytest.mark.asyncio
async def test_check_censys_missing_api_key():
    client = ThreatIntelExtended({'api_keys': {'censys': ''}})

    result = await client.check_censys('203.0.113.10', 'ipv4')

    assert result == {
        'source': 'Censys',
        'status': '⚠',
        'error': 'No valid API key configured',
        'found': False,
    }


@pytest.mark.asyncio
async def test_check_censys_unsupported_ioc_type():
    client = ThreatIntelExtended({'api_keys': {'censys': VALID_CENSYS_PAT}})

    result = await client.check_censys('example.com', 'domain')

    assert result == {
        'source': 'Censys',
        'status': '⚠',
        'error': 'Unsupported type',
        'found': False,
    }
