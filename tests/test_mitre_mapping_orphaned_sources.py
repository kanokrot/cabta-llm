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

    assert text_technique in mapping
