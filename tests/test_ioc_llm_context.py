from types import SimpleNamespace

import pytest

from src.integrations.llm_analyzer import LLMAnalyzer
from src.tools.ioc_investigator import IOCInvestigator


def test_prepare_ioc_context_groups_source_statuses():
    analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
    context = analyzer._prepare_ioc_context(
        'example.com',
        'domain',
        {
            'sources': {
                'degraded': {'status': '⚠', 'error': 'timeout'},
                'not_applicable': {'status': '➖', 'not_applicable': True},
                'found': {'status': '✓', 'found': True},
                'not_found': {'status': '✗', 'found': False},
            }
        },
        dga={'is_dga': True, 'confidence': 85, 'dga_family_guess': 'conficker'},
    )

    assert context['source_status'] == {
        'responded': ['found', 'not_found'],
        'degraded': [{'source': 'degraded', 'reason': 'timeout'}],
        'not_applicable': ['not_applicable'],
    }
    assert context['dga'] == {
        'is_dga': True,
        'confidence': 85,
        'family': 'conficker',
    }


class _StubLLM:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    async def analyze_ioc_results(self, *args, **kwargs):
        if self.error:
            raise self.error
        return self.response


def _make_investigator(monkeypatch, llm):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {
        'analysis': {'enable_llm': True},
        'ticketing': {'create_on_verdict': []},
    }
    investigator.rag_kb = None
    investigator.notification_manager = None
    investigator.llm_analyzer = llm
    async def investigate_ioc_comprehensive(*args, **kwargs):
        return _intel_results()

    investigator.threat_intel = SimpleNamespace(
        investigate_ioc_comprehensive=investigate_ioc_comprehensive
    )

    async def enrich_domain(_domain):
        return {
            'domain_age': {'is_newly_registered': False},
            'dga_analysis': {
                'is_dga': True,
                'confidence': 85,
                'dga_family_guess': 'conficker',
            },
        }

    monkeypatch.setattr(investigator, '_enrich_domain', enrich_domain)
    investigator._trusted_infrastructure_match = lambda *args: None
    monkeypatch.setattr(
        'src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score',
        lambda _results: 0,
    )
    monkeypatch.setattr(
        'src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage',
        lambda _results: {
            'total_sources_attempted': 1,
            'sources_flagged': 0,
            'sources_clean': 1,
        },
    )
    monkeypatch.setattr(
        'src.tools.ioc_investigator.RuleGenerator.generate_ioc_rules',
        lambda *_args: {},
    )
    return investigator


def _intel_results():
    return {
        'sources': {'test_source': {'status': '✓', 'found': False}},
        'sources_checked': 1,
        'sources_flagged': 0,
    }


@pytest.mark.asyncio
async def test_investigate_uses_llm_recommendations_without_dga_injection(monkeypatch):
    llm_recommendations = ['Use the LLM recommendation']
    investigator = _make_investigator(
        monkeypatch,
        _StubLLM(response={
            'verdict': 'CLEAN',
            'analysis': 'No findings.',
            'recommendations': llm_recommendations,
        }),
    )

    result = await investigator.investigate('xkjqmz8fnrpq.com')

    assert result['recommendations'] == llm_recommendations


@pytest.mark.asyncio
async def test_investigate_appends_one_dga_line_on_llm_failure(monkeypatch):
    investigator = _make_investigator(
        monkeypatch,
        _StubLLM(error=RuntimeError('LLM unavailable')),
    )

    result = await investigator.investigate('xkjqmz8fnrpq.com')
    dga_lines = [line for line in result['recommendations'] if 'DGA' in line]

    assert len(dga_lines) == 1
    assert 'confidence=85' in dga_lines[0]
