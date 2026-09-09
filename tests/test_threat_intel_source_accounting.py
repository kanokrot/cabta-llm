from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.integrations.threat_intel import ThreatIntelligence
from src.scoring.intelligent_scoring import IntelligentScoring
from src.utils.helpers import determine_verdict


def _build_hash_intelligence(source_results):
    intelligence = ThreatIntelligence.__new__(ThreatIntelligence)
    intelligence._ioc_cache = Mock()
    intelligence._ioc_cache.get.return_value = None

    intelligence.check_virustotal = AsyncMock(
        return_value=source_results["virustotal"]
    )
    intelligence.check_threatfox = AsyncMock(
        return_value=source_results["threatfox"]
    )
    intelligence.check_malwarebazaar = AsyncMock(
        return_value=source_results["malwarebazaar"]
    )
    intelligence.check_alienvault = AsyncMock(
        return_value=source_results["alienvault"]
    )
    intelligence.extended = SimpleNamespace(
        check_triage=AsyncMock(return_value=source_results["triage"]),
        check_threatzone=AsyncMock(return_value=source_results["threatzone"]),
    )
    return intelligence


@pytest.mark.asyncio
async def test_hash_source_accounting_excludes_unscheduled_placeholders():
    intelligence = _build_hash_intelligence({
        "virustotal": {"status": "✓", "score": 80},
        "threatfox": {"status": "✗", "score": 0},
        "malwarebazaar": {"status": "✗", "score": 0},
        "alienvault": {"status": "✗", "score": 0},
        "triage": {"status": "⚠", "error": "Timeout"},
        "threatzone": {"status": "⚠", "error": "Service unavailable"},
    })

    result = await intelligence.investigate_ioc_comprehensive(
        "a" * 64,
        "sha256",
    )
    coverage = IntelligentScoring.calculate_source_coverage(result)

    assert result["sources_checked"] == 6
    assert result["sources_flagged"] == 1
    assert coverage == {
        "sources_flagged": 1,
        "sources_clean": 3,
        "sources_unavailable": 2,
        "sources_stale": 0,
        "total_sources_attempted": 6,
        "sources_skipped_not_applicable": 18,
    }
    assert result["sources"]["c2_trackers"] == {
        "status": "⏳",
        "message": "Pending",
        "not_applicable": True,
    }


def test_skipped_sources_do_not_inflate_verdict_coverage():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "attempted": {"status": "⚠", "error": "Timeout"},
            **{
                f"skipped_{index}": {
                    "status": "➖",
                    "message": "IP only",
                    "not_applicable": True,
                }
                for index in range(5)
            },
        }
    })

    assert coverage["total_sources_attempted"] == 1
    assert coverage["sources_unavailable"] == 1
    assert coverage["sources_skipped_not_applicable"] == 5
    assert determine_verdict(22, coverage) == "UNKNOWN"
