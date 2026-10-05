from src.scoring.intelligent_scoring import IntelligentScoring


def summary(*states):
    factors = [
        {'key': f'factor_{index}', 'label': '', 'state': state}
        for index, state in enumerate(states)
    ]
    return {
        'found': sum(state == 'found' for state in states),
        'checkable': sum(state in {'found', 'clear'} for state in states),
        'factors': factors,
    }


def test_equal_weight_score_counts_found_factors_only():
    assert IntelligentScoring.calculate_email_score(summary('found', 'clear')) == 50


def test_unavailable_factors_are_excluded_from_denominator():
    assert IntelligentScoring.calculate_email_score(
        summary('found', 'unavailable', 'clear')
    ) == 50


def test_no_found_factors_is_zero():
    assert IntelligentScoring.calculate_email_score(summary('clear', 'clear')) == 0


def test_no_checkable_factors_is_zero():
    assert IntelligentScoring.calculate_email_score(
        summary('unavailable', 'unavailable')
    ) == 0


def test_invalid_summary_is_safe():
    assert IntelligentScoring.calculate_email_score(None) == 0
    assert IntelligentScoring.calculate_email_score({'found': None, 'checkable': 1}) == 0
