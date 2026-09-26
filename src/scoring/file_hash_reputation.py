"""Isolated reputation scoring for file-hash lookups."""


def calculate_file_hash_reputation_score(intel_results: dict) -> dict:
    """Calculate a file-hash reputation score from VT and MalwareBazaar only.

    This scorer is intentionally independent from
    ``IntelligentScoring.calculate_ioc_score()`` and its Group-A source policy.
    """
    sources = intel_results.get('sources', {}) if isinstance(intel_results, dict) else {}

    vt_data = sources.get('virustotal', {}) if isinstance(sources, dict) else {}
    mb_data = sources.get('malwarebazaar', {}) if isinstance(sources, dict) else {}

    vt_score = 0
    contributing_factors = []

    if isinstance(vt_data, dict):
        detections = vt_data.get('detections')
        if isinstance(detections, str) and '/' in detections:
            malicious_text, total_text = detections.split('/', 1)
            try:
                malicious_engines = int(malicious_text)
                total_engines = int(total_text)
            except ValueError:
                malicious_engines = 0
                total_engines = 0

            if malicious_engines > 0 and total_engines > 0:
                vt_score = int((malicious_engines / total_engines) * 100)
                contributing_factors.append(
                    f'{malicious_engines}/{total_engines} VT engines flagged'
                )

    malwarebazaar_score = 0
    if isinstance(mb_data, dict) and mb_data.get('status') == '✓':
        raw_score = mb_data.get('score', 0)
        if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
            malwarebazaar_score = max(0, min(100, int(raw_score)))
        if malwarebazaar_score > 0:
            contributing_factors.append('MalwareBazaar: known malicious sample')

    return {
        'score': max(0, min(100, max(vt_score, malwarebazaar_score))),
        'contributing_factors': contributing_factors,
    }
