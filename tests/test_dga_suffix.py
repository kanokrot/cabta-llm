from src.utils.dga_detector import detect_dga


def test_regional_public_suffixes_are_stripped_before_sld_extraction():
    assert detect_dga('kurs.if.ua')['sld'] == 'kurs'
    assert detect_dga('example.co.uk')['sld'] == 'example'


def test_random_12_character_com_domain_remains_dga():
    result = detect_dga('xkjqmz8fnrpq.com')

    assert result['sld'] == 'xkjqmz8fnrpq'
    assert result['is_dga'] is True
