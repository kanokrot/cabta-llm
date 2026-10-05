from copy import deepcopy
from email.message import EmailMessage

import pytest

from src.tools.email_analyzer import EmailAnalyzer
from src.scoring.intelligent_scoring import IntelligentScoring


def _base_inputs():
    return {
        'email_data': {
            'spf': 'pass',
            'dkim': 'pass',
            'dmarc': 'pass',
            'from': 'sender@example.com',
            'from_domain': 'example.com',
            'return_path': 'bounce@example.com',
            'subject': 'Routine update',
            'body_text': 'Routine message.',
            'body_html': '<p>Routine message.</p>',
            'attachments': [],
            'spam_headers': {'x_spam_flag': 'NO'},
        },
        'header_analysis': {'anomalies': [], 'return_path': 'bounce@example.com'},
        'link_mismatches': [],
        'lookalike_domains': [],
        'html_obfuscation': {
            'zero_size_fonts': 0,
            'hidden_elements': 0,
            'white_on_white': 0,
            'suspicious_css': [],
        },
        'qr_detection': {'qr_codes_found': 0},
        'brand_impersonation': [],
        'threat_indicators': {'active_checks': []},
        'bec_results': {'indicator_count': 0},
        'mixed_script': {
            'found': False,
            'fields': {'subject': [], 'display_name': []},
            'count': 0,
        },
        'forensics': {
            'sender_reputation': {'suspicious_patterns': []},
            'relay_analysis': {
                'suspicious_hops': [],
                'time_anomalies': [],
                'geo_anomalies': [],
            },
        },
        'auth_presence': {'spf': True, 'dkim': True, 'dmarc': True},
    }


def _summary(**updates):
    values = deepcopy(_base_inputs())
    for path, value in updates.items():
        if path == 'auth_presence':
            values[path] = value
        elif path in values:
            values[path] = value
        else:
            if value is None:
                values['email_data'].pop(path, None)
            else:
                values['email_data'][path] = value
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    return analyzer._build_indicator_summary(**values)


def _state(summary, key):
    return next(item['state'] for item in summary['factors'] if item['key'] == key)


@pytest.mark.parametrize(
    ('key', 'updates'),
    [
        ('spf_fail', {'email_data': {'spf': 'fail'}}),
        ('dkim_fail', {'email_data': {'dkim': 'fail'}}),
        ('dmarc_fail', {'email_data': {'dmarc': 'fail'}}),
        ('header_anomaly', {'header_analysis': {'anomalies': ['bad']}}),
        ('link_mismatch', {'link_mismatches': [{'actual_url': 'x'}]}),
        ('lookalike_domain', {'lookalike_domains': [{'domain': 'examp1e.com'}]}),
        ('html_obfuscation', {'html_obfuscation': {'zero_size_fonts': 1}}),
        ('qr_code', {'qr_detection': {'qr_codes_found': 1}}),
        ('brand_impersonation', {'brand_impersonation': [{'brand': 'Example'}]}),
        ('mixed_script', {'mixed_script': {'found': True}}),
        ('phishing_keyword', {'subject': 'Please verify your account'}),
        ('return_path_mismatch', {'return_path': 'bounce@other.example'}),
        ('suspicious_tld', {'from_domain': 'sender.evil.xyz'}),
        ('threat_indicator_finding', {'threat_indicators': {'active_checks': ['x']}}),
        ('bec_finding', {'bec_results': {'indicator_count': 1}}),
        ('spam_header', {'spam_headers': {'x_spam_flag': 'YES'}}),
        ('forensics', {
            'forensics': {
                'sender_reputation': {'suspicious_patterns': ['random username']},
                'relay_analysis': {
                    'suspicious_hops': [],
                    'time_anomalies': [],
                    'geo_anomalies': [],
                },
            },
        }),
    ],
)
def test_each_indicator_is_found_from_its_detector(key, updates):
    if 'email_data' in updates:
        nested = updates['email_data']
        values = _base_inputs()
        values['email_data'].update(nested)
        analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
        result = analyzer._build_indicator_summary(**values)
    else:
        result = _summary(**updates)
    assert _state(result, key) == 'found'


def test_clear_and_unavailable_are_distinct():
    clear = _summary()
    assert all(item['state'] == 'clear' for item in clear['factors'])

    unavailable = _summary(
        auth_presence={'spf': False, 'dkim': False, 'dmarc': False},
        header_analysis={},
        link_mismatches=None,
        lookalike_domains=None,
        html_obfuscation={'risk_score': 0},
        qr_detection=None,
        brand_impersonation=None,
        mixed_script=None,
        subject=None,
        body_text=None,
        return_path='',
        threat_indicators=None,
        bec_results=None,
        spam_headers=None,
        forensics=None,
        **{'from': '', 'from_domain': ''},
    )
    assert _state(unavailable, 'spf_fail') == 'unavailable'
    assert _state(unavailable, 'header_anomaly') == 'unavailable'
    assert _state(unavailable, 'link_mismatch') == 'unavailable'
    assert _state(unavailable, 'html_obfuscation') == 'unavailable'
    assert _state(unavailable, 'spam_header') == 'unavailable'


def test_missing_auth_headers_are_unavailable_not_fail():
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    message = EmailMessage()
    assert analyzer._authentication_header_presence(message) == {
        'spf': False,
        'dkim': False,
        'dmarc': False,
    }
    assert analyzer._check_spf(message) == 'none'
    assert analyzer._check_dkim(message) == 'none'
    assert analyzer._check_dmarc(message) == 'none'

    result = _summary(
        auth_presence={'spf': False, 'dkim': False, 'dmarc': False},
    )
    assert _state(result, 'spf_fail') == 'unavailable'
    assert _state(result, 'dkim_fail') == 'unavailable'
    assert _state(result, 'dmarc_fail') == 'unavailable'


def test_indicator_verdicts_do_not_use_score_thresholds():
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    clean = _summary()
    assert analyzer._determine_indicator_verdict(clean) == 'CLEAN'

    one_finding = _summary(subject='Please verify your account')
    assert analyzer._determine_indicator_verdict(one_finding) == 'SUSPICIOUS'

    link_mismatch = _summary(link_mismatches=[{'actual_url': 'https://example.test'}])
    assert analyzer._determine_indicator_verdict(link_mismatch) == 'SUSPICIOUS'

    link_and_brand = _summary(
        link_mismatches=[{'actual_url': 'https://example.test'}],
        brand_impersonation=[{'brand': 'Example'}],
    )
    assert analyzer._determine_indicator_verdict(link_and_brand) == 'PHISHING'

    impersonation = _summary(brand_impersonation=[{'brand': 'Example'}])
    assert analyzer._determine_indicator_verdict(impersonation) == 'PHISHING'

    unknown = {
        'found': 0,
        'checkable': 0,
        'factors': [{'key': 'x', 'label': 'X', 'state': 'unavailable'}],
    }
    assert analyzer._determine_indicator_verdict(unknown) == 'UNKNOWN'


def test_ioc_results_are_not_an_indicator_or_score_input():
    summary = _summary()
    assert 'ioc_results' not in summary
    assert IntelligentScoring.calculate_email_score(summary) == 0
