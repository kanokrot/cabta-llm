"""Regression tests for Censys enrichment-only scoring behavior."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.threat_intel_extended import ThreatIntelExtended
from src.scoring.intelligent_scoring import IntelligentScoring


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
    return session_context


@pytest.mark.asyncio
async def test_censys_enrichment_does_not_contribute_threat_score_or_flag():
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

    with patch(
        'src.integrations.threat_intel_extended.aiohttp.ClientSession',
        return_value=_mock_client_session(response_data),
    ):
        censys_result = await client.check_censys('8.8.8.8', 'ipv4')

    assert censys_result == {
        'source': 'Censys',
        'found': True,
        'services': 3,
        'location': 'US',
        'autonomous_system': 'EXAMPLE-AS',
        'status': '➖',
    }

    intel_results = {
        'sources': {'censys': censys_result},
        'sources_flagged': 1,
    }

    assert IntelligentScoring.calculate_ioc_score(intel_results) == 0

    coverage = IntelligentScoring.calculate_source_coverage(intel_results)
    assert coverage['sources_flagged'] == 0
    assert coverage['sources_skipped_not_applicable'] == 1
