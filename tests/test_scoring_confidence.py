import pytest

from src.scoring.intelligent_scoring import IntelligentScoring


def test_calculate_ioc_score_output_unchanged_by_new_function():
    intel_results = {
        "sources": {
            "test_source_alpha": {"status": "✓", "score": 15},
            # Synthetic sources use the unknown-source fallback weight (0.8).
            "test_source_beta": {"status": "✓", "score": 138},
        },
        "sources_flagged": 2,
    }

    score_before_coverage = IntelligentScoring.calculate_ioc_score(intel_results)
    IntelligentScoring.calculate_source_coverage(intel_results)
    score_after_coverage = IntelligentScoring.calculate_ioc_score(intel_results)

    assert score_before_coverage == 70
    assert score_after_coverage == score_before_coverage
    assert isinstance(score_after_coverage, int)


def test_all_sources_flagged_high_coverage():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "test_source_alpha": {"status": "✓", "score": 80},
            "test_source_beta": {"status": "✓", "score": 100},
        }
    })

    assert coverage == {
        "sources_flagged": 2,
        "sources_clean": 0,
        "sources_unavailable": 0,
        "sources_stale": 0,
        "total_sources_attempted": 2,
        "sources_skipped_not_applicable": 0,
        "group_a": {
            "sources_flagged": 2,
            "sources_clean": 0,
            "sources_unavailable": 0,
            "sources_stale": 0,
            "total_sources_attempted": 2,
            "sources_skipped_not_applicable": 0,
        },
        "group_b": {
            "sources_flagged": 0,
            "sources_clean": 0,
            "sources_unavailable": 0,
            "sources_stale": 0,
            "total_sources_attempted": 0,
            "sources_skipped_not_applicable": 0,
        },
    }


def test_mixed_clean_and_flagged_counted_separately():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "test_source_alpha": {"status": "✓", "score": 15},
            "test_source_beta": {"status": "✗", "found": False, "score": 0},
        }
    })

    assert coverage["sources_flagged"] == 1
    assert coverage["sources_clean"] == 1
    assert coverage["sources_unavailable"] == 0
    assert coverage["total_sources_attempted"] == 2


def test_timeout_without_cache_counted_unavailable():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "test_source_alpha": {
                "status": "⚠",
                "error": "Timeout",
                "cached": False,
            }
        }
    })

    assert coverage == {
        "sources_flagged": 0,
        "sources_clean": 0,
        "sources_unavailable": 1,
        "sources_stale": 0,
        "total_sources_attempted": 1,
        "sources_skipped_not_applicable": 0,
        "group_a": {
            "sources_flagged": 0,
            "sources_clean": 0,
            "sources_unavailable": 1,
            "sources_stale": 0,
            "total_sources_attempted": 1,
            "sources_skipped_not_applicable": 0,
        },
        "group_b": {
            "sources_flagged": 0,
            "sources_clean": 0,
            "sources_unavailable": 0,
            "sources_stale": 0,
            "total_sources_attempted": 0,
            "sources_skipped_not_applicable": 0,
        },
    }


def test_timeout_with_cache_counted_stale_and_scored():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "test_source_alpha": {
                "status": "✓",
                "score": 100,
                "cached": True,
                "cache_reason": "timeout",
            },
            "test_source_beta": {
                "status": "✗",
                "score": 0,
                "cached": True,
                "cache_reason": "timeout",
            },
        }
    })

    assert coverage == {
        "sources_flagged": 1,
        "sources_clean": 1,
        "sources_unavailable": 0,
        "sources_stale": 2,
        "total_sources_attempted": 2,
        "sources_skipped_not_applicable": 0,
        "group_a": {
            "sources_flagged": 1,
            "sources_clean": 1,
            "sources_unavailable": 0,
            "sources_stale": 2,
            "total_sources_attempted": 2,
            "sources_skipped_not_applicable": 0,
        },
        "group_b": {
            "sources_flagged": 0,
            "sources_clean": 0,
            "sources_unavailable": 0,
            "sources_stale": 0,
            "total_sources_attempted": 0,
            "sources_skipped_not_applicable": 0,
        },
    }


def test_extended_integration_missing_api_key_counted_unavailable_not_clean():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "GreyNoise": {
                "source": "GreyNoise",
                "status": "⚠",
                "error": "No valid API key configured",
                "found": False,
            }
        }
    })

    # Group B availability is informational and must not enter Group A coverage.
    assert coverage["group_b"]["sources_unavailable"] == 1
    assert coverage["group_b"]["sources_clean"] == 0


def test_core_integration_missing_api_key_counted_unavailable_control():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "alienvault": {
                "status": "⚠",
                "error": "No valid API key configured",
            }
        }
    })

    # Group B availability is informational and must not enter Group A coverage.
    assert coverage["group_b"]["sources_unavailable"] == 1
    assert coverage["group_b"]["sources_clean"] == 0


@pytest.mark.parametrize(
    "message",
    [
        "IP only",
        "URL only",
        "Hash only",
        "Domain/IP only",
        "URL/Domain",
        "Domain only",
    ],
)
def test_not_applicable_placeholder_status_is_excluded(message):
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "placeholder": {"status": "➖", "message": message},
        }
    })

    assert coverage == {
        "sources_flagged": 0,
        "sources_clean": 0,
        "sources_unavailable": 0,
        "sources_stale": 0,
        "total_sources_attempted": 0,
        "sources_skipped_not_applicable": 1,
        "group_a": {
            "sources_flagged": 0,
            "sources_clean": 0,
            "sources_unavailable": 0,
            "sources_stale": 0,
            "total_sources_attempted": 0,
            "sources_skipped_not_applicable": 1,
        },
        "group_b": {
            "sources_flagged": 0,
            "sources_clean": 0,
            "sources_unavailable": 0,
            "sources_stale": 0,
            "total_sources_attempted": 0,
            "sources_skipped_not_applicable": 0,
        },
    }


def test_explicit_not_applicable_marker_excludes_pending_placeholder():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "c2_trackers": {
                "status": "⏳",
                "message": "Pending",
                "not_applicable": True,
            },
        }
    })

    assert coverage["sources_skipped_not_applicable"] == 1
    assert coverage["total_sources_attempted"] == 0
    assert coverage["sources_clean"] == 0


@pytest.mark.parametrize(
    ("reason_key", "reason_value"),
    [
        ("message", "Not applicable"),
        ("error", "Not applicable"),
    ],
)
def test_legacy_not_applicable_reason_is_excluded(reason_key, reason_value):
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "legacy_source": {reason_key: reason_value},
        }
    })

    assert coverage["sources_skipped_not_applicable"] == 1
    assert coverage["total_sources_attempted"] == 0
    assert coverage["sources_clean"] == 0
