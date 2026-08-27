import pytest
from src.integrations.verdict_validator import compute_authoritative_verdict


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