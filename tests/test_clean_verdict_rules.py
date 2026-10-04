from unittest.mock import AsyncMock

import pytest
import yaml

from src.detection.rule_generator import RuleGenerator
from src.detection.rule_validator import validate_rule
from src.integrations.llm_analyzer import LLMAnalyzer
from src.tools.ioc_investigator import IOCInvestigator
from src.agent.tool_registry import ToolRegistry


EXPECTED_CLEAN_KEYS = {'kql', 'spl', 'sigma', 'xql', 'dql', 'suricata'}
NETWORK_RULE_KEYS = ('kql', 'spl', 'xql', 'dql', 'suricata')


@pytest.mark.parametrize('verdict', ['CLEAN', 'clean', ' Clean '])
def test_clean_ioc_rules_omit_firewall(verdict):
    clean = RuleGenerator.generate_ioc_rules('kurs.if.ua', 'domain', {'verdict': verdict})
    malicious = RuleGenerator.generate_ioc_rules(
        'kurs.if.ua', 'domain', {'verdict': 'MALICIOUS'}
    )

    assert set(clean) == EXPECTED_CLEAN_KEYS
    for key in NETWORK_RULE_KEYS:
        assert clean[key] == malicious[key]


def test_clean_sigma_is_informational_and_valid():
    sigma_text = RuleGenerator.generate_ioc_rules(
        'kurs.if.ua', 'domain', {'verdict': 'clean'}
    )['sigma']
    document = yaml.safe_load(sigma_text)

    assert document['level'] == 'informational'
    assert not any(tag.startswith('attack.') for tag in document['tags'])
    assert document['title'].startswith('Hunt for')
    assert validate_rule('sigma', sigma_text)['valid'] is True


@pytest.mark.parametrize(
    'context',
    [
        {'verdict': 'MALICIOUS'},
        {'verdict': 'SUSPICIOUS'},
        {'verdict': 'Unknown'},
        {'verdict': None},
        {},
        None,
    ],
)
def test_non_clean_verdicts_keep_existing_rule_behavior(context):
    rules = RuleGenerator.generate_ioc_rules('kurs.if.ua', 'domain', context)
    assert 'action=deny' in rules['firewall']
    sigma = yaml.safe_load(rules['sigma'])
    assert sigma['tags'] == ['attack.command-and-control', 'attack.t1071']

    expected_level = {
        'MALICIOUS': 'critical',
        'SUSPICIOUS': 'high',
    }.get((context or {}).get('verdict') if context else None, 'medium')
    assert sigma['level'] == expected_level


class _StubLLM:
    def __init__(self, verdict):
        self.verdict = verdict
        self.translate_calls = 0
        self.translate_awaited = False

    async def analyze_ioc_results(self, *args, **kwargs):
        return {}

    async def translate_firewall_to_fortigate(self, *args, **kwargs):
        self.translate_calls += 1
        self.translate_awaited = True
        return 'config firewall address\n    edit "kurs.if.ua"\nend'


def _make_investigator(monkeypatch, llm, verdict):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {
        'analysis': {'enable_llm': True},
        'ticketing': {'create_on_verdict': []},
    }
    investigator.rag_kb = None
    investigator.notification_manager = None
    investigator.llm_analyzer = llm

    class ThreatIntel:
        async def investigate_ioc_comprehensive(self, *args, **kwargs):
            return {
                'sources': {'test_source': {'status': '✓', 'found': False}},
                'sources_checked': 1,
                'sources_flagged': 0,
            }

    investigator.threat_intel = ThreatIntel()
    investigator._trusted_infrastructure_match = lambda *args: None
    async def enrich_domain(_domain):
        return None

    investigator._enrich_domain = enrich_domain
    monkeypatch.setattr(
        'src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score',
        lambda _results: 0 if verdict == 'CLEAN' else 80,
    )
    monkeypatch.setattr(
        'src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage',
        lambda _results: {
            'total_sources_attempted': 1,
            'sources_flagged': 0 if verdict == 'CLEAN' else 1,
            'sources_clean': 1,
        },
    )
    return investigator


@pytest.mark.asyncio
async def test_investigator_skips_clean_and_translates_malicious(monkeypatch):
    clean_llm = _StubLLM('CLEAN')
    clean_investigator = _make_investigator(monkeypatch, clean_llm, 'CLEAN')
    clean_result = await clean_investigator.investigate('kurs.if.ua')
    assert clean_result['verdict'] == 'CLEAN'
    assert clean_llm.translate_calls == 0
    assert 'firewall' not in clean_result['detection_rules']
    assert 'firewall_fortigate' not in clean_result['detection_rules']

    malicious_llm = _StubLLM('MALICIOUS')
    malicious_investigator = _make_investigator(monkeypatch, malicious_llm, 'MALICIOUS')
    malicious_result = await malicious_investigator.investigate('kurs.if.ua')
    assert malicious_result['verdict'] == 'MALICIOUS'
    assert malicious_llm.translate_calls == 1
    assert 'firewall_fortigate' in malicious_result['detection_rules']


def test_clean_hash_rules_omit_firewall_without_crashing():
    rules = RuleGenerator.generate_ioc_rules(
        'a' * 64, 'sha256', {'verdict': 'CLEAN'}
    )
    assert set(rules) == EXPECTED_CLEAN_KEYS


@pytest.mark.asyncio
async def test_tool_registry_skips_absent_firewall_rule(monkeypatch):
    registry = ToolRegistry()
    registry.register_default_tools({})

    monkeypatch.setattr(
        RuleGenerator,
        'generate_ioc_rules',
        lambda *_args: {'suricata': 'suricata rule'},
    )
    result = await registry.execute_local_tool(
        'generate_rules',
        analysis_result={
            'result': {
                'capabilities': [{'name': 'network'}],
                'mitre_attacks': [{'id': 'T1071'}],
            }
        },
        network_iocs=['kurs.if.ua'],
    )

    assert 'error' not in result
    assert result['rules']['suricata'] == ['suricata rule']
    assert 'firewall' not in result['rules']


@pytest.mark.asyncio
async def test_translate_clean_or_comment_never_calls_provider():
    analyzer = LLMAnalyzer({'llm': {'provider': 'vllm'}})
    provider = AsyncMock(return_value={'fortigate_cli': 'config firewall\nedit x\nend'})
    analyzer._call_vllm_api = provider

    assert await analyzer.translate_firewall_to_fortigate(
        'action=deny indicator="kurs.if.ua"',
        'kurs.if.ua',
        'domain',
        'CLEAN',
        'Unknown',
    ) is None
    assert await analyzer.translate_firewall_to_fortigate(
        '# No block rule generated: verdict CLEAN. Review before any enforcement.',
        'kurs.if.ua',
        'domain',
        'MALICIOUS',
        'Unknown',
    ) is None
    provider.assert_not_awaited()
