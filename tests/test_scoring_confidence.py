from src.scoring.intelligent_scoring import IntelligentScoring


def test_calculate_ioc_score_output_unchanged_by_new_function():
    intel_results = {
        "sources": {
            "virustotal": {"status": "✓", "score": 15},
            "alienvault": {"status": "✓", "score": 100},
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
            "virustotal": {"status": "✓", "score": 80},
            "alienvault": {"status": "✓", "score": 100},
        }
    })

    assert coverage == {
        "sources_flagged": 2,
        "sources_clean": 0,
        "sources_unavailable": 0,
        "sources_stale": 0,
        "total_sources_attempted": 2,
    }


def test_mixed_clean_and_flagged_counted_separately():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "virustotal": {"status": "✓", "score": 15},
            "threatfox": {"status": "✗", "found": False, "score": 0},
        }
    })

    assert coverage["sources_flagged"] == 1
    assert coverage["sources_clean"] == 1
    assert coverage["sources_unavailable"] == 0
    assert coverage["total_sources_attempted"] == 2


def test_timeout_without_cache_counted_unavailable():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "alienvault": {
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
    }


def test_timeout_with_cache_counted_stale_and_scored():
    coverage = IntelligentScoring.calculate_source_coverage({
        "sources": {
            "alienvault": {
                "status": "✓",
                "score": 100,
                "cached": True,
                "cache_reason": "timeout",
            },
            "threatfox": {
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
    }
