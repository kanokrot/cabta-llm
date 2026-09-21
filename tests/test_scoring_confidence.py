import pytest

from src.scoring.intelligent_scoring import (
    IntelligentScoring,
    SOURCE_SCORING_MULTIPLIERS,
)


def test_report_only_sources_do_not_change_ioc_score():
    intel_results = {
        "sources": {
            "test_source_alpha": {"status": "✓", "score": 15},
            # Unknown sources are report-only under the feed-only policy.
            "test_source_beta": {"status": "✓", "score": 138},
        },
        "sources_flagged": 2,
    }

    score_before_coverage = IntelligentScoring.calculate_ioc_score(intel_results)
    IntelligentScoring.calculate_source_coverage(intel_results)
    score_after_coverage = IntelligentScoring.calculate_ioc_score(intel_results)

    assert score_before_coverage == 0
    assert score_after_coverage == score_before_coverage
    assert isinstance(score_after_coverage, int)


def test_api_sources_are_report_only_and_do_not_trigger_boost():
    score = IntelligentScoring.calculate_ioc_score({
        "sources": {
            "feodotracker": {"status": "✓", "score": 60},
            "usom": {"status": "✓", "score": 100},
            "virustotal": {"status": "✓", "score": 100},
        }
    })

    # Only FeodoTracker contributes. With one source, the AHP multiplier is
    # present in both the numerator and denominator, so the score remains 60.
    # API/query results do not contribute or count toward the multi-source boost.
    assert score == 60


def test_active_source_multipliers_match_ahp_derivation():
    # Values are derived in docs/source_weight_ahp_derivation_2026-09-16.md.
    assert SOURCE_SCORING_MULTIPLIERS == {
        "feodotracker": 1.500000,
        "sslblacklist": 0.878018,
        "spamhaus": 0.695930,
        "tor_exit_nodes": 0.542480,
        "c2_trackers": 0.442818,
        "threatfox": 0.339610,
    }


def test_threatfox_available_result_uses_ahp_multiplier():
    score = IntelligentScoring.calculate_ioc_score({
        "sources": {
            "threatfox": {"status": "✓", "score": 100},
        }
    })

    assert score == 100


def test_threatfox_timeout_is_excluded_not_clean_or_scored():
    intel_results = {
        "sources": {
            "threatfox": {
                "status": "⚠",
                "error": "Timeout after 15s",
                "found": False,
                "score": 0,
                "unavailable": True,
                "timeout": True,
                "cached": False,
            }
        }
    }

    assert IntelligentScoring.calculate_ioc_score(intel_results) == 0
    coverage = IntelligentScoring.calculate_source_coverage(intel_results)
    assert coverage["sources_unavailable"] == 1
    assert coverage["sources_clean"] == 0


def test_non_api_tiered_sources_use_their_explicit_tier():
    score = IntelligentScoring.calculate_ioc_score({
        "sources": {
            "feodotracker": {"status": "✓", "score": 100},
            "c2_trackers": {"status": "✓", "score": 100},
        }
    })

    # Average of the AHP multipliers for FeodoTracker and C2 Trackers,
    # followed by the two-source boost.
    assert score == 100


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
