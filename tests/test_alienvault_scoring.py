"""Regression tests for AlienVault OTX pulse qualification."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from src.integrations.threat_intel import ThreatIntelligence


VALID_ALIENVAULT_KEY = "alienvault_key_123456"


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
    return session_context


def _client():
    client = ThreatIntelligence.__new__(ThreatIntelligence)
    client.api_keys = {'alienvault': VALID_ALIENVAULT_KEY}
    client.timeout = aiohttp.ClientTimeout(total=30)
    return client


async def _check(response_data, ioc='9.9.9.9', ioc_type='ipv4'):
    with patch(
        'src.integrations.threat_intel.aiohttp.ClientSession',
        return_value=_mock_client_session(response_data),
    ):
        return await _client().check_alienvault(ioc, ioc_type)


@pytest.mark.asyncio
async def test_whitelist_validation_overrides_high_raw_pulse_count():
    result = await _check({
        'indicator': 'wikipedia.org',
        'validation': [
            {
                'source': 'whitelist',
                'name': 'Whitelisted domain',
                'message': 'Whitelisted domain wikipedia.org',
            },
            {'source': 'akamai', 'name': 'Akamai Popular Domain'},
        ],
        'pulse_info': {
            'count': 50,
            'pulses': [
                {
                    'name': 'Clone Credit: Disable_Duck',
                    'malware_families': [],
                    'adversary': '',
                    'attack_ids': [],
                }
            ],
        },
    }, ioc='wikipedia.org', ioc_type='domain')

    assert result['status'] == '✗'
    assert result['score'] == 0
    assert result['total_pulses'] == 50


@pytest.mark.asyncio
async def test_all_junk_pulses_do_not_score_even_when_raw_count_is_high():
    result = await _check({
        'indicator': '9.9.9.9',
        'pulse_info': {
            'count': 50,
            'pulses': [
                {
                    'name': 'Auto-generated Pulse',
                    'tags': ['auto-generated security'],
                    'malware_families': [],
                    'adversary': '',
                    'attack_ids': [],
                }
                for _ in range(5)
            ],
        },
    })

    assert result['status'] == '✗'
    assert result['score'] == 0
    assert result['total_pulses'] == 50
    assert result['qualified_pulses'] == 0


@pytest.mark.asyncio
async def test_qualified_pulse_still_scores_and_preserves_raw_count():
    result = await _check({
        'indicator': '203.0.113.10',
        'pulse_info': {
            'count': 50,
            'pulses': [
                {
                    'name': 'Confirmed malware infrastructure',
                    'malware_families': ['ExampleFamily'],
                    'adversary': '',
                    'attack_ids': [],
                },
                {
                    'name': 'Auto-generated Pulse',
                    'malware_families': [],
                    'adversary': '',
                    'attack_ids': [],
                },
            ],
        },
    })

    assert result['status'] == '✓'
    assert result['score'] > 0
    assert result['score'] == 10
    assert result['total_pulses'] == 50
    assert result['qualified_pulses'] == 1
