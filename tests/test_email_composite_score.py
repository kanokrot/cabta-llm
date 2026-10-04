from src.scoring.intelligent_scoring import IntelligentScoring


def score(base_score, ioc_results=None, attachment_results=None):
    return IntelligentScoring.calculate_email_score(
        base_score,
        ioc_results,
        attachment_results,
    )


def test_base_score_is_kept_without_ioc_or_attachment_evidence():
    assert score(70) == 70


def test_malicious_ioc_score_is_not_diluted_by_base_score():
    assert score(20, [{'verdict': 'MALICIOUS', 'threat_score': 100}]) == 100


def test_clean_ioc_does_not_reduce_a_higher_base_score():
    assert score(80, [{'verdict': 'CLEAN', 'threat_score': 0}]) == 80


def test_scores_above_100_are_clamped():
    assert score(150) == 100
    assert score(20, [{'verdict': 'CLEAN', 'threat_score': 150}]) == 100


def test_negative_and_none_scores_are_safe():
    assert score(-10) == 0
    assert score(None) == 0
    assert score(20, [{'verdict': 'CLEAN', 'threat_score': None}]) == 20
