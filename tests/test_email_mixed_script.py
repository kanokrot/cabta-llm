from src.analyzers.advanced_email_analyzer import AdvancedEmailAnalyzer
from src.tools.email_analyzer import EmailAnalyzer


def test_subject_mixed_script_is_reported():
    result = AdvancedEmailAnalyzer.detect_mixed_script(
        'Соngrаtulаtіоns yоur іtеm sоld',
        None,
    )

    assert result['found'] is True
    assert result['fields']['subject']
    assert result['count'] == len(result['fields']['subject'])


def test_plain_latin_subject_is_not_reported():
    result = AdvancedEmailAnalyzer.detect_mixed_script(
        'Congratulations your item sold',
        None,
    )

    assert result == {
        'found': False,
        'fields': {'subject': [], 'display_name': []},
        'count': 0,
    }


def test_thai_and_latin_are_not_treated_as_mixed_target_scripts():
    result = AdvancedEmailAnalyzer.detect_mixed_script(
        'ยืนยันคำสั่งซื้อ iPhone 15',
        None,
    )

    assert result['found'] is False


def test_different_script_words_are_not_one_mixed_token():
    result = AdvancedEmailAnalyzer.detect_mixed_script('Привет world', None)

    assert result['found'] is False


def test_greek_and_latin_in_one_token_are_reported():
    result = AdvancedEmailAnalyzer.detect_mixed_script('Payπαl', None)

    assert result['found'] is True
    assert result['fields']['subject'] == ['Payπαl']


def test_display_name_mixed_script_is_reported():
    result = AdvancedEmailAnalyzer.detect_mixed_script(
        None,
        'PаyPal <sender@example.com>',
    )

    assert result['found'] is True
    assert result['fields']['display_name'] == ['PаyPal']


def test_empty_subject_and_from_are_safe():
    result = AdvancedEmailAnalyzer.detect_mixed_script(None, None)

    assert result['found'] is False
    assert result['count'] == 0


def test_mixed_script_output_is_bounded():
    result = AdvancedEmailAnalyzer.detect_mixed_script(
        ' '.join(['PаyPal'] * 20),
        'PаyPal <sender@example.com>',
    )

    returned = result['fields']['subject'] + result['fields']['display_name']
    assert len(returned) <= 10
    assert all(len(token) <= 64 for token in returned)


def _base_score(analyzer, mixed_script, **email_overrides):
    email_data = {
        'spf': 'pass',
        'dkim': 'pass',
        'dmarc': 'pass',
        'forensics_score': 0,
        'spam_headers': {},
        'body_text': '',
        'subject': '',
        'from': '',
        'return_path': '',
        **email_overrides,
    }
    return analyzer._calculate_base_phishing_score(
        email_data,
        {'anomalies': []},
        [],
        [],
        {'risk_score': 0},
        {'qr_codes_found': 0},
        [],
        {},
        {},
        mixed_script,
    )


def test_mixed_script_is_one_equal_weight_factor():
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    not_found = {'found': False, 'fields': {'subject': [], 'display_name': []}, 'count': 0}
    found = {'found': True, 'fields': {'subject': ['PаyPal'], 'display_name': []}, 'count': 1}

    assert _base_score(analyzer, not_found) == 0
    assert _base_score(analyzer, found) == 11


def test_mixed_script_score_stays_within_indicator_range():
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    found = {'found': True, 'fields': {'subject': ['PаyPal'], 'display_name': []}, 'count': 1}

    score = _base_score(
        analyzer,
        found,
        spf='fail',
        dkim='fail',
        forensics_score=80,
        spam_headers={'x_spam_flag': 'YES'},
        subject='[spam] urgent verify account password',
        **{'from': 'sender@evil.xyz', 'return_path': 'bounce@other.xyz'},
    )

    assert 0 <= score <= 100
