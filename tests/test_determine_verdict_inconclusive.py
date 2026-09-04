import pytest

from src.utils.helpers import determine_verdict


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "CLEAN"),
        (39, "CLEAN"),
        (40, "SUSPICIOUS"),
        (69, "SUSPICIOUS"),
        (70, "MALICIOUS"),
        (100, "MALICIOUS"),
    ],
)
def test_no_coverage_arg_preserves_legacy_behavior(score, expected):
    assert determine_verdict(score) == expected


def test_low_coverage_returns_unknown():
    coverage = {
        "sources_flagged": 1,
        "sources_clean": 0,
        "sources_unavailable": 3,
        "sources_stale": 0,
        "total_sources_attempted": 4,
    }

    assert determine_verdict(22, coverage) == "UNKNOWN"


def test_high_confidence_flag_overrides_low_coverage():
    coverage = {
        "sources_flagged": 1,
        "sources_clean": 0,
        "sources_unavailable": 9,
        "sources_stale": 0,
        "total_sources_attempted": 10,
    }

    assert determine_verdict(70, coverage) == "MALICIOUS"


def test_full_coverage_high_score_still_malicious():
    coverage = {
        "sources_flagged": 2,
        "sources_clean": 4,
        "sources_unavailable": 0,
        "sources_stale": 0,
        "total_sources_attempted": 6,
    }

    assert determine_verdict(85, coverage) == "MALICIOUS"
