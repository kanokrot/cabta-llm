from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.tools.ioc_investigator import IOCInvestigator, _safe_ai_error


class StubLLM:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.analyze_ioc_results = AsyncMock(side_effect=error, return_value=response)



def _make_investigator(monkeypatch, llm, *, enabled=True):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {
        "analysis": {"enable_llm": enabled},
        "ticketing": {"create_on_verdict": []},
    }
    investigator.rag_kb = None
    investigator.notification_manager = None
    investigator.llm_analyzer = llm

    async def investigate_ioc_comprehensive(*args, **kwargs):
        return {
            "sources": {"test_source": {"status": "ok", "found": False}},
            "sources_checked": 1,
            "sources_flagged": 0,
        }

    investigator.threat_intel = SimpleNamespace(
        investigate_ioc_comprehensive=investigate_ioc_comprehensive
    )
    investigator._trusted_infrastructure_match = lambda *args: None

    async def enrich_domain(_domain):
        return None

    investigator._enrich_domain = enrich_domain
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score",
        lambda _results: 0,
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage",
        lambda _results: {
            "total_sources_attempted": 1,
            "sources_flagged": 0,
            "sources_clean": 1,
        },
    )
    monkeypatch.setattr(
        "src.tools.ioc_investigator.RuleGenerator.generate_ioc_rules",
        lambda *_args: {},
    )
    return investigator


@pytest.mark.asyncio
async def test_ai_status_complete_when_llm_recommendations_are_used(monkeypatch):
    llm = StubLLM(response={"recommendations": ["review traffic"]})
    investigator = _make_investigator(monkeypatch, llm)

    result = await investigator.investigate("example.com")

    assert result["recommendations_source"] == "llm"
    assert result["ai_status"] == "complete"
    assert result["ai_error"] is None


@pytest.mark.parametrize(
    "failure",
    [
        None,
        {"error": "provider error"},
        RuntimeError("provider error"),
    ],
)
@pytest.mark.asyncio
async def test_ai_status_failed_for_llm_failures(monkeypatch, failure):
    if isinstance(failure, Exception):
        llm = StubLLM(error=failure)
    else:
        llm = StubLLM(response=failure)
    investigator = _make_investigator(monkeypatch, llm)

    result = await investigator.investigate("example.com")

    assert result["recommendations_source"] == "rule_based"
    assert result["ai_status"] == "failed"
    assert isinstance(result["ai_error"], str)
    assert len(result["ai_error"]) <= 300


@pytest.mark.asyncio
async def test_ai_status_disabled_when_llm_config_is_disabled(monkeypatch):
    llm = StubLLM(response={"recommendations": ["should not be used"]})
    investigator = _make_investigator(monkeypatch, llm, enabled=False)

    result = await investigator.investigate("example.com")

    assert result["ai_status"] == "disabled"
    assert result["ai_error"] is None
    llm.analyze_ioc_results.assert_not_awaited()


def test_ai_error_redacts_urls_and_credentials():
    error = _safe_ai_error(
        'request failed https://llm.test/v1?api_key=secret Authorization: Bearer private'
    )

    assert error is not None
    assert 'https://' not in error
    assert 'secret' not in error
    assert 'private' not in error
    assert '[REDACTED]' in error
