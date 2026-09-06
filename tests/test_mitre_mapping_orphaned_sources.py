"""Regression tests for MITRE sources consumed by MalwareAnalyzer."""

from src.tools.malware_analyzer import MalwareAnalyzer


def test_generate_mitre_mapping_includes_text_analyzer_techniques():
    analyzer = MalwareAnalyzer.__new__(MalwareAnalyzer)
    text_technique = {
        'technique_id': 'T1204.002',
        'source': 'text_analysis',
        'context': 'Malicious File',
        'confidence': 'medium',
    }
    static_analysis = {
        'mitre_techniques': [text_technique],
        'suspicious_patterns': {'categories': {}},
    }

    mapping = analyzer._generate_mitre_mapping(static_analysis, {}, {})

    matching = next(
        (item for item in mapping if item.get('technique_id') == text_technique['technique_id']),
        None,
    )
    assert matching is not None
    for key, value in text_technique.items():
        assert matching[key] == value


def test_generate_mitre_mapping_enriches_known_static_pattern_technique():
    analyzer = MalwareAnalyzer.__new__(MalwareAnalyzer)
    static_analysis = {
        'suspicious_patterns': {
            'categories': {
                'execution': {'count': 1},
            },
        },
    }

    mapping = analyzer._generate_mitre_mapping(static_analysis, {}, {})
    technique = next(item for item in mapping if item['technique_id'] == 'T1059')

    assert technique['technique'] == 'Command and Scripting Interpreter'
    assert technique['tactic'] == 'Execution'


def test_generate_mitre_mapping_does_not_fabricate_unknown_technique_name():
    analyzer = MalwareAnalyzer.__new__(MalwareAnalyzer)
    sandbox = {
        'summary': {
            'mitre_techniques': ['T9999.999'],
        },
    }

    mapping = analyzer._generate_mitre_mapping({}, sandbox, {})
    technique = next(item for item in mapping if item['technique_id'] == 'T9999.999')

    assert 'technique' not in technique
    assert 'tactic' not in technique
