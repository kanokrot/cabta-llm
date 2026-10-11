from src.integrations.verdict_validator import validate_llm_analysis


ALL_KNOWN_SOURCES = [
    "c2_trackers",
    "greynoise",
    "talos",
    "ip2proxy",
    "responded_feed",
    "not_applicable_feed",
    "fakesource",
]


def _validate(analysis, source_status):
    return validate_llm_analysis(
        {"analysis": analysis},
        {"key_findings": [], "source_status": source_status},
        all_known_sources=ALL_KNOWN_SOURCES,
    )


def test_scored_and_context_degraded_sources_are_allowlisted():
    result = _validate(
        "c2_trackers, greynoise, talos, and ip2proxy were degraded.",
        {
            "responded": [],
            "not_applicable": [],
            "scored_degraded": [
                {"source": "c2_trackers", "reason": "timeout"},
            ],
            "context_degraded": [
                {"source": "greynoise", "reason": "timeout"},
                {"source": "talos", "reason": "timeout"},
                {"source": "ip2proxy", "reason": "timeout"},
            ],
        },
    )

    assert "hallucination_warning" not in result


def test_responded_and_not_applicable_sources_remain_allowlisted():
    result = _validate(
        "responded_feed responded, and not_applicable_feed is not applicable.",
        {
            "responded": ["responded_feed"],
            "not_applicable": ["not_applicable_feed"],
            "scored_degraded": [],
            "context_degraded": [],
        },
    )

    assert "hallucination_warning" not in result


def test_degraded_status_accepts_string_entries_and_legacy_key():
    result = _validate(
        "c2_trackers, greynoise, and talos were degraded.",
        {
            "responded": [],
            "not_applicable": [],
            "scored_degraded": ["c2_trackers"],
            "context_degraded": ["greynoise"],
            "degraded": ["talos"],
        },
    )

    assert "hallucination_warning" not in result


def test_source_missing_from_status_lists_still_warns():
    result = _validate(
        "fakesource reported activity.",
        {
            "responded": [],
            "not_applicable": [],
            "scored_degraded": [],
            "context_degraded": [],
        },
    )

    assert "hallucination_warning" in result
