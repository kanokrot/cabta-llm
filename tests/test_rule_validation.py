import pytest

from src.detection.rule_validator import validate_rule


VALID_SIGMA = """title: Suspicious process
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: cmd.exe
  condition: selection
"""

VALID_YARA = """rule Suspicious_File {
    strings:
        $marker = "cabta-test"
    condition:
        $marker
}
"""


@pytest.mark.parametrize(
    ('rule_type', 'content'),
    [
        ('kql', 'DeviceProcessEvents\n| where FileName == "cmd.exe"'),
        ('spl', 'index=main | search process_name="cmd.exe"'),
        ('xql', 'dataset = xdr_data | filter event_type = PROCESS'),
        ('dql', 'process.name:"cmd.exe" and event.code:1'),
    ],
)
def test_query_rule_basic_validation_accepts_balanced_content(rule_type, content):
    assert validate_rule(rule_type, content) == {
        'valid': True,
        'errors': [],
        'rule_type': rule_type,
    }


@pytest.mark.parametrize('rule_type', ['kql', 'spl', 'xql', 'dql'])
def test_query_rule_basic_validation_rejects_unbalanced_syntax(rule_type):
    result = validate_rule(rule_type, 'query | where field == "unterminated')

    assert result['valid'] is False
    assert result['rule_type'] == rule_type
    assert 'Unterminated " quote' in result['errors']


def test_sigma_uses_yaml_parser_and_requires_core_sigma_shape():
    assert validate_rule('sigma', VALID_SIGMA)['valid'] is True

    malformed = validate_rule('sigma', 'title: Test\ndetection: [')
    assert malformed['valid'] is False
    assert malformed['errors'][0].startswith('Sigma YAML syntax error:')

    missing_shape = validate_rule('sigma', 'title: Test')
    assert missing_shape['valid'] is False
    assert 'Sigma rule is missing required field: logsource' in missing_shape['errors']
    assert 'Sigma rule is missing required field: detection' in missing_shape['errors']


def test_yara_uses_yara_python_compiler():
    assert validate_rule('yara', VALID_YARA)['valid'] is True

    malformed = validate_rule('yara', 'rule Broken { condition: }')
    assert malformed['valid'] is False
    assert malformed['errors'][0].startswith('YARA syntax error:')


@pytest.mark.parametrize('rule_type', ['suricata', 'snort'])
def test_network_rule_structural_validation(rule_type):
    valid_rule = (
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
        '(msg:"CABTA test"; sid:1000001; rev:1;)'
    )
    assert validate_rule(rule_type, valid_rule)['valid'] is True

    invalid = validate_rule(rule_type, 'alert tcp $HOME_NET any')
    assert invalid['valid'] is False
    assert 'must contain an action, header, direction, and options' in invalid['errors'][0]


def test_firewall_structural_validation():
    valid = 'action=deny indicator_type=ipv4 indicator="203.0.113.5"'
    assert validate_rule('firewall', valid)['valid'] is True

    invalid = validate_rule('firewall', 'send this somewhere')
    assert invalid['valid'] is False
    assert invalid['errors'] == [
        'Firewall rule must use key/value entries or a recognized '
        'allow, deny, block, permit, or configuration command'
    ]


def test_empty_and_unsupported_rule_types_are_invalid():
    assert validate_rule('kql', '  ')['errors'] == [
        'Rule content must be a non-empty string'
    ]
    assert validate_rule('elastic-eql', 'process where true') == {
        'valid': False,
        'errors': ['Unsupported rule type: elastic-eql'],
        'rule_type': 'elastic-eql',
    }
