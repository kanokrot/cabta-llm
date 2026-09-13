"""Tests for deduplicating AlienVault pulse threat attributions."""

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


async def _check(response_data, ioc='example.test', ioc_type='domain'):
    client = ThreatIntelligence.__new__(ThreatIntelligence)
    client.api_keys = {'alienvault': VALID_ALIENVAULT_KEY}
    client.timeout = aiohttp.ClientTimeout(total=30)

    with patch(
        'src.integrations.threat_intel.aiohttp.ClientSession',
        return_value=_mock_client_session(response_data),
    ):
        return await client.check_alienvault(ioc, ioc_type)


def _pulse(*, families=None, adversary='', attack_ids=None):
    return {
        'malware_families': families or [],
        'adversary': adversary,
        'attack_ids': attack_ids or [],
    }


@pytest.mark.asyncio
async def test_hicloudcam_duplicate_family_counts_one_attribution():
    result = await _check({
        'pulse_info': {
            'count': 50,
            'pulses': [
                _pulse(families=['Cobalt Strike'])
                for _ in range(44)
            ],
        },
    }, ioc='hicloudcam.com')

    assert result['qualified_pulses'] == 44
    assert result['unique_attribution_count'] == 1
    assert result['score'] == 10


@pytest.mark.asyncio
async def test_dzen_distinct_families_remain_distinct():
    result = await _check({
        'pulse_info': {
            'count': 11,
            'pulses': [
                _pulse(families=['Family One']),
                _pulse(families=['Family Two']),
            ],
        },
    }, ioc='dzen.ru')

    assert result['qualified_pulses'] == 2
    assert result['unique_attribution_count'] == 2
    assert result['score'] == 20


@pytest.mark.asyncio
async def test_malicious_single_attack_id_keeps_score_ten():
    result = await _check({
        'pulse_info': {
            'count': 1,
            'pulses': [_pulse(attack_ids=['T1059'])],
        },
    }, ioc='203.0.113.10', ioc_type='ipv4')

    assert result['qualified_pulses'] == 1
    assert result['unique_attribution_count'] == 1
    assert result['score'] == 10


@pytest.mark.asyncio
async def test_distinct_families_receive_diversity_score():
    result = await _check({
        'pulse_info': {
            'count': 5,
            'pulses': [
                _pulse(families=[f'Family {index}'])
                for index in range(5)
            ],
        },
    })

    assert result['qualified_pulses'] == 5
    assert result['unique_attribution_count'] == 5
    assert result['score'] == 50


@pytest.mark.asyncio
async def test_pulses_without_attribution_are_not_flagged():
    result = await _check({
        'pulse_info': {
            'count': 5,
            'pulses': [_pulse() for _ in range(5)],
        },
    })

    assert result['qualified_pulses'] == 0
    assert result['unique_attribution_count'] == 0
    assert result['status'] == '\u2717'


@pytest.mark.asyncio
async def test_qualified_pulses_field_is_preserved_for_backward_compatibility():
    result = await _check({
        'pulse_info': {
            'count': 2,
            'pulses': [
                _pulse(families=['Repeated Family']),
                _pulse(families=['Repeated Family']),
            ],
        },
    })

    assert 'qualified_pulses' in result
    assert result['qualified_pulses'] == 2
    assert result['unique_attribution_count'] == 1

