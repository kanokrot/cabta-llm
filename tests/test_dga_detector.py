"""
Tests for DGA detection module.
"""

from src.utils.dga_detector import detect_dga


def test_common_words_reduce_dga_confidence():
    result = detect_dga('creditrepairhacking.com')
    dictionary_match = result['dictionary_match']

    assert {'credit', 'repair', 'hacking'} <= set(dictionary_match['words_found'])
    assert dictionary_match['coverage'] > 0.3158
    assert result['confidence'] < 28
