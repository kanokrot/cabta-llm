"""Regression tests for supported MITRE mapping input shapes."""

from src.reporting.mitre_navigator import generate_navigator_layer


def test_generate_navigator_layer_accepts_list_mapping():
    result = generate_navigator_layer({
        'mitre_mapping': [
            {
                'technique_id': 'T1059',
                'tactic': 'execution',
                'confidence': 'high',
            },
            {
                'technique_id': 'T1486',
                'tactic': 'impact',
                'confidence': 'high',
            },
        ]
    })

    technique_ids = {item['techniqueID'] for item in result['techniques']}
    assert technique_ids == {'T1059', 'T1486'}


def test_generate_navigator_layer_preserves_dict_mapping():
    result = generate_navigator_layer({
        'mitre_mapping': {
            'T1059': {
                'tactic': 'execution',
                'confidence': 'high',
            }
        }
    })

    assert [item['techniqueID'] for item in result['techniques']] == ['T1059']
