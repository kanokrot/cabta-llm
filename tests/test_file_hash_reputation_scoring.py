from src.scoring.file_hash_reputation import calculate_file_hash_reputation_score


def test_vt_positive_only_uses_linear_detection_ratio():
    result = calculate_file_hash_reputation_score({
        'sources': {
            'virustotal': {'status': '✓', 'detections': '12/70', 'score': 60},
            'malwarebazaar': {'status': '✗', 'message': 'Not found'},
        }
    })

    assert result['score'] == 17
    assert result['contributing_factors'] == ['12/70 VT engines flagged']


def test_malwarebazaar_positive_only_uses_confirmed_sample_score():
    result = calculate_file_hash_reputation_score({
        'sources': {
            'virustotal': {'status': '✗', 'detections': '0/70'},
            'malwarebazaar': {
                'status': '✓',
                'signature': 'Example.Malware',
                'file_type': 'exe',
                'score': 95,
            },
        }
    })

    assert result['score'] == 95
    assert result['contributing_factors'] == [
        'MalwareBazaar: known malicious sample'
    ]


def test_both_positive_uses_maximum_not_average():
    result = calculate_file_hash_reputation_score({
        'sources': {
            'virustotal': {'status': '✓', 'detections': '80/100'},
            'malwarebazaar': {'status': '✓', 'score': 95},
        }
    })

    assert result['score'] == 95
    assert '80/100 VT engines flagged' in result['contributing_factors']
    assert 'MalwareBazaar: known malicious sample' in result['contributing_factors']


def test_clean_or_unavailable_sources_score_zero():
    result = calculate_file_hash_reputation_score({
        'sources': {
            'virustotal': {'status': '⚠', 'error': 'Timeout'},
            'malwarebazaar': {'status': '✗', 'message': 'Not found'},
        }
    })

    assert result == {'score': 0, 'contributing_factors': []}


def test_group_a_sources_are_ignored():
    result = calculate_file_hash_reputation_score({
        'sources': {
            'threatfox': {'status': '✓', 'score': 100},
            'feodotracker': {'status': '✓', 'score': 100},
        }
    })

    assert result == {'score': 0, 'contributing_factors': []}
