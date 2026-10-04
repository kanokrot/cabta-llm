from src.integrations.verdict_validator import validate_llm_analysis


def _validate(analysis, source_status):
    context = {"key_findings": []}
    if source_status is not _MISSING:
        context["source_status"] = source_status
    return validate_llm_analysis(
        {"analysis": analysis},
        context,
        all_known_sources=["circl", "shodan", "greynoise"],
    )


class _Missing:
    pass


_MISSING = _Missing()


def test_degraded_source_is_not_flagged_as_hallucinated():
    result = _validate(
        "circl reported a degraded response.",
        {"responded": [], "degraded": [{"source": "circl", "reason": "HTTP 401"}], "not_applicable": []},
    )

    assert "hallucination_warning" not in result


def test_not_applicable_source_is_not_flagged_as_hallucinated():
    result = _validate(
        "shodan is not applicable for this IOC.",
        {"responded": [], "degraded": [], "not_applicable": ["shodan"]},
    )

    assert "hallucination_warning" not in result


def test_source_absent_from_all_context_lists_still_warns():
    result = _validate(
        "greynoise reported activity.",
        {"responded": [], "degraded": [], "not_applicable": []},
    )

    assert "hallucination_warning" in result


def test_missing_none_and_malformed_source_status_are_safe_and_preserve_behavior():
    malformed_values = [
        _MISSING,
        None,
        {},
        {"responded": "shodan", "degraded": "circl", "not_applicable": 1},
        {"responded": [1, None], "degraded": ["circl", {"source": 3}], "not_applicable": [False]},
    ]

    for source_status in malformed_values:
        result = _validate("greynoise reported activity.", source_status)
        assert "hallucination_warning" in result
