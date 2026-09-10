import pytest
from src.integrations.verdict_validator import (
    compute_authoritative_verdict,
    validate_llm_analysis,
)
from src.utils.helpers import determine_verdict


def _coverage(*, flagged, clean, total):
    return {
        "sources_flagged": flagged,
        "sources_clean": clean,
        "sources_unavailable": total - flagged - clean,
        "sources_stale": 0,
        "total_sources_attempted": total,
    }


def _validated_verdict(score, authoritative_verdict):
    result = validate_llm_analysis(
        {"verdict": compute_authoritative_verdict(score)},
        context={},
        threat_score=score,
        authoritative_verdict=authoritative_verdict,
    )
    return result


class TestComputeAuthoritativeVerdict:
    def test_zero_score_is_clean_not_unknown(self):
        # regression test: บั๊กเดิมที่ threat_score=0 กลายเป็น UNKNOWN
        assert compute_authoritative_verdict(0) == "CLEAN"

    def test_score_one_is_clean(self):
        assert compute_authoritative_verdict(1) == "CLEAN"

    def test_score_39_is_clean(self):
        assert compute_authoritative_verdict(39) == "CLEAN"

    def test_score_40_is_suspicious(self):
        assert compute_authoritative_verdict(40) == "SUSPICIOUS"

    def test_score_69_is_suspicious(self):
        assert compute_authoritative_verdict(69) == "SUSPICIOUS"

    def test_score_70_is_malicious(self):
        assert compute_authoritative_verdict(70) == "MALICIOUS"

    def test_score_100_is_malicious(self):
        assert compute_authoritative_verdict(100) == "MALICIOUS"

    def test_negative_score_is_unknown(self):
        assert compute_authoritative_verdict(-1) == "UNKNOWN"


class TestPrecomputedAuthoritativeVerdict:
    def test_score_22_low_coverage_uses_top_level_unknown(self):
        coverage = _coverage(flagged=1, clean=0, total=4)
        top_level = determine_verdict(22, coverage)

        result = _validated_verdict(22, top_level)

        assert result["verdict"] == top_level == "UNKNOWN"
        assert "corrected to 'UNKNOWN'" in result["verdict_override_note"]

    @pytest.mark.parametrize("score", [40, 69])
    def test_suspicious_score_low_coverage_uses_top_level_unknown(self, score):
        coverage = _coverage(flagged=1, clean=0, total=4)
        top_level = determine_verdict(score, coverage)

        assert _validated_verdict(score, top_level)["verdict"] == "UNKNOWN"

    def test_high_score_without_flag_low_coverage_uses_unknown(self):
        coverage = _coverage(flagged=0, clean=1, total=4)
        top_level = determine_verdict(70, coverage)

        assert _validated_verdict(70, top_level)["verdict"] == "UNKNOWN"

    def test_high_score_with_flag_preserves_malicious_exception(self):
        coverage = _coverage(flagged=1, clean=0, total=10)
        top_level = determine_verdict(70, coverage)

        assert _validated_verdict(70, top_level)["verdict"] == "MALICIOUS"

    @pytest.mark.parametrize(
        ("clean", "expected"),
        [
            (29, "UNKNOWN"),
            (30, "CLEAN"),
        ],
    )
    def test_coverage_ratio_boundary(self, clean, expected):
        coverage = _coverage(flagged=0, clean=clean, total=100)
        top_level = determine_verdict(22, coverage)

        assert _validated_verdict(22, top_level)["verdict"] == expected

    def test_none_authoritative_verdict_falls_back_to_score_only_behavior(self):
        result = validate_llm_analysis(
            {"verdict": "UNKNOWN"},
            context={},
            threat_score=22,
            authoritative_verdict=None,
        )

        assert result["verdict"] == compute_authoritative_verdict(22) == "CLEAN"
        assert "corrected to 'CLEAN'" in result["verdict_override_note"]
