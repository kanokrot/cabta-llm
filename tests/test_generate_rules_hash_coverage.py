"""Coverage for literal hash IOC types in detection-rule generation."""

import pytest

from src.agent.tool_registry import ToolRegistry
from src.detection.rule_generator import RuleGenerator


HASH_IOCS = (
    ('hash', 'd' * 64),
    ('md5', 'a' * 32),
    ('sha1', 'b' * 40),
    ('sha256', 'c' * 64),
)

LITERAL_HASH_IOCS = HASH_IOCS[1:]


def _assert_supported_hash_rule(rule: str, ioc: str) -> None:
    assert 'not supported' not in rule.lower()
    assert 'unsupported' not in rule.lower()
    assert ioc in rule


@pytest.mark.parametrize(
    'generator',
    (
        RuleGenerator._generate_kql_ioc,
        RuleGenerator._generate_spl_ioc,
        RuleGenerator._generate_dql_ioc,
    ),
)
@pytest.mark.parametrize('ioc_type,ioc', LITERAL_HASH_IOCS)
def test_literal_hash_types_are_supported_by_kql_spl_and_dql(
    generator, ioc_type, ioc
):
    rule = generator(ioc, ioc_type, {})

    _assert_supported_hash_rule(rule, ioc)


@pytest.mark.parametrize('ioc_type,ioc', HASH_IOCS)
def test_hash_types_are_supported_by_xql(ioc_type, ioc):
    rule = RuleGenerator._generate_xql_ioc(ioc, ioc_type, {})

    _assert_supported_hash_rule(rule, ioc)


@pytest.mark.parametrize('ioc_type,ioc', HASH_IOCS)
def test_generate_ioc_rules_supports_hash_types_end_to_end(ioc_type, ioc):
    rules = RuleGenerator.generate_ioc_rules(ioc, ioc_type, {})

    for rule_type in ('kql', 'spl', 'dql', 'xql', 'sigma'):
        _assert_supported_hash_rule(rules[rule_type], ioc)


@pytest.mark.parametrize('ioc_type,ioc', LITERAL_HASH_IOCS)
def test_network_only_formats_remain_unsupported_for_hash_types(ioc_type, ioc):
    rules = RuleGenerator.generate_ioc_rules(ioc, ioc_type, {})

    assert 'not supported' in rules['suricata'].lower()
    assert 'not supported' in rules['firewall'].lower()


@pytest.mark.asyncio
async def test_aggregate_shape_maps_md5_sha1_and_sha256_lists():
    registry = ToolRegistry()
    registry.register_default_tools({})
    aggregate_hashes = {
        'md5': ['a' * 32],
        'sha1': ['b' * 40],
        'sha256': ['c' * 64],
    }

    result = await registry.execute_local_tool(
        'generate_rules', analysis_result=aggregate_hashes
    )

    assert 'error' not in result
    for rule_type in ('kql', 'spl', 'dql', 'xql'):
        rules = result['rules'][rule_type]
        assert len(rules) == 3
        for hashes in aggregate_hashes.values():
            _assert_supported_hash_rule(rules.pop(0), hashes[0])
