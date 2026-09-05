from unittest.mock import AsyncMock

import pytest

from src.integrations.llm_analyzer import LLMAnalyzer
from src.tools.ioc_investigator import IOCInvestigator


CLI = 'config firewall address\n    edit "blocked-ioc"\n        set subnet 1.2.3.4 255.255.255.255\n    next\nend'
ABSTRACT = 'action=deny indicator_type=ipv4 indicator="1.2.3.4"'


@pytest.mark.asyncio
@pytest.mark.parametrize('provider', ['ollama', 'vllm', 'anthropic'])
async def test_translation_returns_cli_from_configured_provider(provider):
    analyzer = LLMAnalyzer({'llm': {'provider': provider}})
    for name in ('ollama', 'vllm', 'anthropic'):
        setattr(analyzer, f'_call_{name}_api', AsyncMock(return_value={'fortigate_cli': CLI}))

    result = await analyzer.translate_firewall_to_fortigate(
        ABSTRACT, '1.2.3.4', 'ipv4', 'MALICIOUS', 'Emotet'
    )

    assert result == CLI
    for name in ('ollama', 'vllm', 'anthropic'):
        backend = getattr(analyzer, f'_call_{name}_api')
        if name == provider:
            backend.assert_awaited_once()
            prompt = backend.await_args.args[0]
            for value in (ABSTRACT, '1.2.3.4', 'ipv4', 'MALICIOUS', 'Emotet'):
                assert value in prompt
        else:
            backend.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('response', [
    {'analysis': 'No CLI available'},
    {'fortigate_cli': 'config firewall address\nend'},
    {'fortigate_cli': ''},
    {'fortigate_cli': '   '},
    {'fortigate_cli': {'config': 'firewall'}},
    'not a JSON object',
    None,
])
async def test_translation_discards_unavailable_or_invalid_output(response):
    analyzer = LLMAnalyzer({'llm': {'provider': 'vllm'}})
    analyzer._call_vllm_api = AsyncMock(return_value=response)

    assert await analyzer.translate_firewall_to_fortigate(
        ABSTRACT, '1.2.3.4', 'ipv4', 'MALICIOUS', 'Emotet'
    ) is None


@pytest.mark.asyncio
async def test_translation_catches_provider_exception():
    analyzer = LLMAnalyzer({'llm': {'provider': 'vllm'}})
    analyzer._call_vllm_api = AsyncMock(side_effect=RuntimeError('backend unavailable'))

    assert await analyzer.translate_firewall_to_fortigate(
        ABSTRACT, '1.2.3.4', 'ipv4', 'MALICIOUS', 'Emotet'
    ) is None


@pytest.fixture
def investigator(monkeypatch):
    instance = IOCInvestigator.__new__(IOCInvestigator)
    instance.config = {'analysis': {'enable_llm': True}}
    instance.rag_kb = None
    instance.threat_intel = AsyncMock()
    instance.threat_intel.investigate_ioc_comprehensive.return_value = {
        'sources': {'threatfox': {'malware_family': 'Emotet'}},
        'sources_checked': 1,
        'sources_flagged': 1,
    }
    instance.llm_analyzer = AsyncMock(spec=LLMAnalyzer)
    instance.llm_analyzer.analyze_ioc_results.return_value = {}
    instance.llm_analyzer.translate_firewall_to_fortigate.return_value = CLI
    monkeypatch.setattr(
        'src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score',
        lambda _results: 80,
    )
    monkeypatch.setattr(
        'src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage',
        lambda _results: {
            'total_sources_attempted': 1,
            'successful_sources': 1,
            'coverage_percentage': 100,
        },
    )
    return instance


@pytest.mark.asyncio
@pytest.mark.parametrize('translation', [CLI, None])
async def test_investigate_only_adds_fortigate_key_on_success(investigator, translation):
    investigator.llm_analyzer.translate_firewall_to_fortigate.return_value = translation

    result = await investigator.investigate('1.2.3.4')

    rules = result['detection_rules']
    assert isinstance(rules['firewall'], str)
    investigator.llm_analyzer.translate_firewall_to_fortigate.assert_awaited_once_with(
        rules['firewall'], '1.2.3.4', result['ioc_type'], result['verdict'], 'Emotet'
    )
    if translation:
        assert rules['firewall_fortigate'] == translation
    else:
        assert 'firewall_fortigate' not in rules


@pytest.mark.asyncio
async def test_investigate_translation_exception_is_non_fatal(investigator):
    investigator.llm_analyzer.translate_firewall_to_fortigate.side_effect = RuntimeError('unavailable')

    result = await investigator.investigate('1.2.3.4')

    assert 'firewall_fortigate' not in result['detection_rules']
    assert result['detection_rules']['firewall']


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['disabled', 'unsupported_type', 'missing_firewall'])
async def test_investigate_skips_translation(investigator, monkeypatch, reason):
    ioc = '1.2.3.4'
    if reason == 'disabled':
        investigator.config['analysis']['enable_llm'] = False
    elif reason == 'unsupported_type':
        ioc = 'a' * 64
    else:
        monkeypatch.setattr(
            'src.tools.ioc_investigator.RuleGenerator.generate_ioc_rules',
            lambda *_args: {'kql': 'existing rule'},
        )

    result = await investigator.investigate(ioc)

    investigator.llm_analyzer.translate_firewall_to_fortigate.assert_not_awaited()
    assert 'firewall_fortigate' not in result['detection_rules']
