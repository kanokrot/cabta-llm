"""
Tests for DGA detection module.
"""

import pytest

from src.utils.dga_detector import (
    _DICTIONARY_WORDS,
    check_dictionary_words,
    detect_dga,
)


def test_dictionary_supplement_is_loaded():
    assert len(_DICTIONARY_WORDS) >= 5000
    assert 'check' in _DICTIONARY_WORDS
    assert 'bot' in _DICTIONARY_WORDS


def test_historical_dictionary_matching_case():
    result = check_dictionary_words('checkbot-cf')

    assert result['word_count'] == 2
    assert {'check', 'bot'} <= set(result['words_found'])


def test_common_words_reduce_dga_confidence():
    result = detect_dga('creditrepairhacking.com')
    dictionary_match = result['dictionary_match']

    assert {'credit', 'repair', 'hacking'} <= set(dictionary_match['words_found'])
    assert dictionary_match['coverage'] > 0.3158
    assert result['confidence'] == 30


def test_dga_like_subdomain_contributes_to_confidence():
    result = detect_dga('wa83neqa.example.com')

    assert result['confidence'] == 54
    assert result['is_dga'] is True


@pytest.mark.parametrize(
    'domain',
    [
        'www.google.com',
        'ns2.example.net',
        'cdn3.site.com',
        'api2.stripe.com',
        'mail.company.com',
    ],
)
def test_common_infrastructure_subdomains_are_not_dga(domain):
    result = detect_dga(domain)

    assert result['is_dga'] is False


def test_original_motivating_case_now_detected():
    result = detect_dga('wa83neqa.creditrepairhacking.com')

    assert result['confidence'] == 54
    assert result['is_dga'] is True


@pytest.mark.parametrize(
    'domain',
    [
        'google.com',
        'stripe.com',
        'github.com',
        'wikipedia.org',
        'www.google.com',
        'api.stripe.com',
        'docs.github.com',
        'mail.company.com',
        'ns2.example.net',
        'cdn3.site.com',
        'vpn.corp.local',
    ],
)
def test_validation_legit_domains_remain_not_dga(domain):
    result = detect_dga(domain)

    assert result['is_dga'] is False


@pytest.mark.parametrize(
    'domain',
    [
        'xkjqmz8fnrpqwlst.com',
        'trk9v2x1.example.com',
        'n5c2v8b6.edge.example.net',
    ],
)
def test_validation_simulated_dga_domains_are_dga(domain):
    result = detect_dga(domain)

    assert result['is_dga'] is True
