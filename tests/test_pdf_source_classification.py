"""Focused tests for PDF display helpers and shared source accounting."""

from datetime import datetime, timezone

import pytest

from src.reporting.ioc_pdf import (
    SOURCE_STATUS_COLORS,
    _defang_ioc,
    _format_header_timestamp,
    _na_label,
    _source_detail_text,
    _source_rows,
    _text,
    _without_emoji,
    generate_ioc_pdf,
)
from src.web.source_classification import (
    classify_source,
    count_source_classes,
    source_status_label,
)


def test_source_counts_match_report_template_categories():
    sources = {
        "threatfox": {"status": "flagged", "score": 90},
        "virustotal": {"status": "✓", "score": 30},
        "alienvault": {"status": "clean", "score": 0},
        "circl": {"status": "⚠", "error": "HTTP 401"},
        "feed": {"status": "➖", "not_applicable": True},
        "empty": {},
    }
    assert count_source_classes(sources) == {
        "flagged": 1,
        "responded": 3,
        "errors": 1,
        "na": 2,
    }


@pytest.mark.parametrize(
    ("source_data", "expected"),
    [
        ({"status": None}, "clean"),
        ({"status": ""}, "na"),
        ({}, "na"),
        ({"status": "Not found"}, "clean"),
    ],
)
def test_source_status_edge_cases_match_report_template(source_data, expected):
    assert classify_source(source_data) == expected


def test_pdf_status_labels_distinguish_reported_from_flagged():
    assert source_status_label({"status": "flagged", "score": 90}) == "FLAGGED"
    assert source_status_label({"status": "✓", "score": 30}) == "REPORTED"
    assert source_status_label({"status": "clean", "score": 0}) == "CLEAN"
    assert source_status_label({"status": "⚠", "error": "timeout"}) == "ERROR"
    assert source_status_label({"status": "➖"}) == "N/A"


def test_pdf_source_rows_use_compact_human_readable_details():
    rows = _source_rows({
        "threatfox": {
            "status": "flagged",
            "score": 90,
            "confidence": 100,
            "first_seen": "2026-09-12",
        },
        "not_applicable": {"status": "➖", "not_applicable": True},
    })

    assert rows[0] == ["Source", "Result", "Detail"]
    assert rows[1][0:2] == ["ThreatFox", "FLAGGED"]
    assert rows[1][2] == "Listed. Confidence 100%, score 90, first seen 2026-09-12."
    assert len(rows) == 2


@pytest.mark.parametrize(
    ("source_data", "expected"),
    [
        ({"error": "HTTP 401"}, "Authentication failed (HTTP 401). Source not evaluated."),
        ({"error": "HTTP 403"}, "Authentication failed (HTTP 403). Source not evaluated."),
        ({"error": "HTTP 500"}, "Request failed (HTTP 500). Source not evaluated."),
        ({"feed_status": "unavailable"}, "Feed unavailable. Source not evaluated."),
        ({"error": "<script>x</script> C:\\secret\\key"}, "Source error. Source not evaluated."),
    ],
)
def test_pdf_source_detail_error_cases_are_safe(source_data, expected):
    detail = _source_detail_text("source", source_data, "error", "domain")
    assert detail == expected
    assert "<script>" not in detail
    assert "C:\\secret\\key" not in detail


def test_pdf_source_detail_uses_safe_http_status_without_error_text():
    assert _source_detail_text(
        "circl", {"http_status": 401}, "error", "domain"
    ) == "Authentication failed (HTTP 401). Source not evaluated."


def test_pdf_source_detail_reported_non_scoring_source_adds_context():
    detail = _source_detail_text(
        "example_report_only",
        {"status": "✓", "score": 30},
        "other",
        "domain",
    )
    assert detail == "No additional detail Context only, not part of the score."


def test_pdf_source_detail_virustotal_uses_recorded_detection_values():
    source_data = {
        "status": "✓",
        "score": 30,
        "detections": "6/91",
        "last_analysis": "2026-09-25",
    }
    assert _source_detail_text("virustotal", source_data, "other", "domain") == (
        "6 of 91 engines, last analysis 2026-09-25. Context only, not part of the score."
    )
    assert _source_detail_text(
        "virustotal", {"detections": "6/91"}, "other", "domain"
    ) == "6 of 91 engines."


def test_pdf_source_detail_threatfox_uses_only_present_fields():
    assert _source_detail_text(
        "threatfox",
        {
            "confidence": 100,
            "score": 90,
            "first_seen": "2026-09-12 11:36:45 UTC",
        },
        "flagged",
        "domain",
    ) == "Listed. Confidence 100%, score 90, first seen 2026-09-12."
    assert _source_detail_text("threatfox", {"score": 90}, "flagged", "domain") == (
        "Listed. score 90."
    )
    assert _source_detail_text("threatfox", {}, "flagged", "domain") == "Listed."


def test_pdf_source_detail_clean_and_fallback_cases():
    assert _source_detail_text(
        "c2_trackers", {"sources_checked": 10}, "clean", "domain"
    ) == "Not found in 10 trackers."
    assert _source_detail_text("clean_source", {}, "clean", "domain") == "Not found."
    assert _source_detail_text("other_source", {}, "other", "domain") == "No additional detail"


@pytest.mark.parametrize(
    ("ioc_type", "expected"),
    [
        ("domain", "N/A FOR DOMAINS"),
        ("ip", "N/A FOR IPS"),
        ("ipv4", "N/A FOR IPS"),
        ("ipv6", "N/A FOR IPS"),
        ("hash", "N/A FOR HASHES"),
        ("md5", "N/A FOR HASHES"),
        ("sha1", "N/A FOR HASHES"),
        ("sha256", "N/A FOR HASHES"),
        ("url", "N/A FOR URLS"),
        ("unknown", "N/A"),
        (None, "N/A"),
    ],
)
def test_pdf_na_label_by_ioc_type(ioc_type, expected):
    assert _na_label(ioc_type) == expected


def test_reported_badge_is_blue_and_clean_badge_is_green():
    reported_background, reported_foreground = SOURCE_STATUS_COLORS["REPORTED"]
    clean_background, clean_foreground = SOURCE_STATUS_COLORS["CLEAN"]
    assert (reported_background, reported_foreground) == ("#e6eef7", "#0c447c")
    assert (clean_background, clean_foreground) == ("#e8f5e9", "#1b5e20")
    assert reported_background != clean_background
    assert reported_foreground != clean_foreground


def test_pdf_defanging_is_display_only_and_emoji_removal_keeps_thai():
    assert _defang_ioc("example.test", "domain") == "example[.]test"
    assert _defang_ioc("https://example.test/a", "url") == "hxxps://example[.]test/a"
    assert _defang_ioc("user@example.test", "email") == "user[@]example[.]test"
    assert _without_emoji("New 🆕 domain: ภัยคุกคาม") == "New  domain: ภัยคุกคาม"
    assert not any(char in _text("■ ✓ ✗ ➖ ⚠") for char in "■✓✗➖⚠")


def test_header_timestamp_formats_iso_epoch_and_none():
    assert _format_header_timestamp("2026-10-07T12:34:56+07:00") == "2026-10-07 05:34 UTC"
    assert _format_header_timestamp(0) == "1970-01-01 00:00 UTC"
    assert _format_header_timestamp(None) == "N/A"
    assert _format_header_timestamp(datetime(2026, 10, 7, tzinfo=timezone.utc)) == "2026-10-07 00:00 UTC"


@pytest.mark.parametrize("analysis_type", ["ioc", "file", "email", "unknown"])
def test_generate_pdf_for_each_analysis_type(tmp_path, analysis_type):
    output_path = tmp_path / f"{analysis_type}.pdf"
    result = {
        "ioc": "example.test",
        "ioc_type": "domain",
        "verdict": "CLEAN",
        "threat_score": 0,
        "sources": {},
        "summary": "Example analysis summary",
        "llm_analysis": {},
    }

    generated_path = generate_ioc_pdf(
        result,
        str(output_path),
        metadata={"analysis_type": analysis_type},
    )

    pdf_bytes = output_path.read_bytes()
    assert generated_path == str(output_path)
    assert pdf_bytes
    assert pdf_bytes.startswith(b"%PDF")
