import re
from datetime import datetime

import pytest
import yaml

from src.detection.rule_generator import RuleGenerator
from src.detection.rule_validator import validate_rule


EDGE_VALUES = {
    'apostrophe': "evil'.example",
    'hash_char': 'evil.example/#frag',
    'colon': 'evil.example:8080',
    'newline': 'evil.example\nlevel: low',
    'mixed': "a'b #c: d\ne",
}

DETECTION_PATHS = {
    'ipv4': [('selection_dst', 'dst_ip'), ('selection_src', 'src_ip')],
    'domain': [('selection', 'query|contains')],
    'url': [('selection', 'c-uri|contains')],
    'sha256': [('selection', 'Hashes|contains')],
}

ALLOWED_TOP_KEYS = {
    'title', 'id', 'status', 'description', 'author', 'date', 'references',
    'tags', 'logsource', 'detection', 'fields', 'falsepositives', 'level',
}


@pytest.mark.parametrize('ioc_type', list(DETECTION_PATHS))
@pytest.mark.parametrize('ioc', list(EDGE_VALUES.values()), ids=list(EDGE_VALUES))
def test_generated_sigma_roundtrips_edge_values(ioc_type, ioc):
    text = RuleGenerator.generate_ioc_rules(ioc, ioc_type, {})['sigma']
    doc = yaml.safe_load(text)

    for block, key in DETECTION_PATHS[ioc_type]:
        assert doc['detection'][block][key] == ioc
    assert set(doc) <= ALLOWED_TOP_KEYS
    assert doc['level'] == 'medium'


@pytest.mark.parametrize('ioc_type', list(DETECTION_PATHS))
@pytest.mark.parametrize('ioc', list(EDGE_VALUES.values()), ids=list(EDGE_VALUES))
def test_generated_sigma_passes_validator(ioc_type, ioc):
    text = RuleGenerator.generate_ioc_rules(ioc, ioc_type, {})['sigma']
    result = validate_rule('sigma', text)
    assert result['valid'] is True
    assert result['syntax_valid'] is True


def test_sigma_fallback_status_is_schema_only():
    text = RuleGenerator.generate_ioc_rules(
        '203.0.113.42', 'ipv4', {}
    )['sigma']
    result = validate_rule('sigma', text)
    assert result['status'] == 'schema_only'


def test_context_fields_are_escaped():
    family = "Emo'tet: #1\nx"
    ioc = 'evil.example'
    context = {'malware_family': family, 'verdict': 'MALICIOUS'}
    doc = yaml.safe_load(
        RuleGenerator.generate_ioc_rules(ioc, 'domain', context)['sigma']
    )
    assert doc['title'] == f'Detection of {family} IOC - {ioc}'
    assert doc['level'] == 'critical'
    assert set(doc) <= ALLOWED_TOP_KEYS


def test_generic_fallback_branch_roundtrips():
    ioc = "x'y #z: w\nv"
    doc = yaml.safe_load(RuleGenerator._generate_sigma_ioc(ioc, 'mutex', {}))
    assert [list(item.values())[0] for item in doc['detection']['selection']] == [ioc] * 3


def test_normal_ioc_keeps_single_quoted_format():
    text = RuleGenerator.generate_ioc_rules(
        '203.0.113.42', 'ipv4', {}
    )['sigma']
    assert "dst_ip: '203.0.113.42'" in text


def _assert_sigma_metadata(doc):
    assert doc['tags'] == ['attack.command-and-control', 'attack.t1071']
    assert isinstance(doc['date'], str)
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}', doc['date'])
    datetime.strptime(doc['date'], '%Y-%m-%d')


@pytest.mark.parametrize('ioc_type', list(DETECTION_PATHS))
def test_generated_sigma_metadata_uses_spec_format(ioc_type):
    text = RuleGenerator.generate_ioc_rules(
        '203.0.113.42', ioc_type, {}
    )['sigma']
    _assert_sigma_metadata(yaml.safe_load(text))


def test_generic_sigma_metadata_uses_spec_format():
    text = RuleGenerator._generate_sigma_ioc(
        'mutex-value', 'mutex', {}
    )
    _assert_sigma_metadata(yaml.safe_load(text))
