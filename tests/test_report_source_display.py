from collections import Counter
from pathlib import Path
import re
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.web.report_source_display import (
    SOURCE_LABELS,
    build_source_display_rows,
    display_source_name,
    display_source_status,
)
from src.scoring.intelligent_scoring import SOURCE_SCORING_MULTIPLIERS


def _render_report(sources, *, print_mode=False):
    templates_dir = Path(__file__).resolve().parents[1] / "templates"
    environment = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    request = SimpleNamespace(
        query_params={"print": "1"} if print_mode else {},
        url=SimpleNamespace(path="/api/reports/display-test/html"),
        state=SimpleNamespace(user={"role": "admin"}),
    )
    job = {
        "id": "display-test",
        "analysis_type": "ioc",
        "status": "completed",
        "created_at": "2026-10-05T06:50:00+00:00",
        "completed_at": "2026-10-05T06:51:00+00:00",
        "result": {
            "ioc": "example.com",
            "ioc_type": "domain",
            "threat_score": 90,
            "sources": sources,
            "recommendations": [],
            "recommendations_rule_based": [],
            "detection_rules": {},
            "domain_enrichment": {},
        },
    }
    return environment.get_template("report_view.html").render(
        request=request,
        job=job,
        build_source_display_rows=build_source_display_rows,
        display_source_name=display_source_name,
    )


def _count_fixture_sources():
    sources = {
        "threatfox": {"status": "found", "score": 90, "confidence": 100},
        "virustotal": {"status": "\u2713", "score": 30, "detections": "6/91"},
        "circl": {"status": "error", "score": 0, "error": "HTTP 401"},
        "misp_circl_feed_osint": {
            "status": "unavailable",
            "score": 0,
            "feed_status": "unavailable",
            "message": "IOC not found in MISP feed cache",
        },
    }
    sources.update(
        {f"responded-{index}": {"status": "clean", "score": 0} for index in range(5)}
    )
    sources.update(
        {
            f"na-{index}": {"status": "\u2796", "not_applicable": True}
            for index in range(19)
        }
    )
    return sources


def test_source_name_map_and_fallback():
    assert SOURCE_LABELS["threatfox"] == "ThreatFox"
    assert display_source_name("virustotal") == "VirusTotal"
    assert display_source_name("misp_circl_feed_osint") == "MISP CIRCL feed"
    assert display_source_name("some_unknown_feed") == "Some Unknown Feed"


def test_symbol_status_maps_to_score_word_and_zero_to_clean():
    assert display_source_status("other", "\u2713", 30) == "LOW"
    assert display_source_status("clean", "\u2713", 0) == "Clean"
    assert display_source_status("clean", "\u2717", 0) == "Clean"
    assert display_source_status("na", "\u2796", 0) == "N/A"
    assert display_source_status("clean", "\u23f3", 0) == "Pending"
    assert display_source_status("error", "\u26a0", 0) == "Error"


def test_summary_uses_source_whitelist_and_keeps_full_text_for_title():
    row = build_source_display_rows(
        {
            "threatfox": {
                "status": "found",
                "score": 90,
                "confidence": 100,
                "first_seen": "2026-09-12 11:36 UTC " + ("x" * 45),
                "threat_type": "botnet_cc",
                "unlisted_noise": "must not enter summary",
            }
        },
        {"threatfox": "flagged"},
    )[0]

    assert len(row["summary"]) <= 60
    assert "confidence 100" in row["summary"]
    assert "unlisted_noise" not in row["summary"]
    assert "must not enter summary" not in row["summary"]
    assert "unlisted_noise" not in row["summary_title"]
    assert "first_seen" in {field["key"].replace(" ", "_") for field in row["detail_fields"]}


def test_unknown_source_summary_uses_first_three_nonempty_pairs():
    row = build_source_display_rows(
        {
            "custom_feed": {
                "status": "found",
                "score": 80,
                "first_value": "one",
                "empty_value": "",
                "second_value": "two",
                "third_value": "three",
                "fourth_value": "four",
            }
        },
        {"custom_feed": "flagged"},
    )[0]

    assert row["summary"] == "first value one / second value two / third value three"
    assert "fourth value" not in row["summary"]


def test_c2_negative_summary_keeps_checked_count_and_boolean_without_empty_lists():
    row = build_source_display_rows(
        {
            "c2_trackers": {
                "status": "\u2717",
                "found": False,
                "is_c2": False,
                "sources_checked": 10,
                "sources_found": [],
                "malware_families": [],
                "score": 0,
            }
        },
        {"c2_trackers": "clean"},
    )[0]

    assert row["summary"] == "10 feeds checked / is C2 False"
    assert "sources_found" not in row["summary"]
    assert "malware_families" not in row["summary"]


def test_error_row_displays_error_badge_and_reason():
    row = build_source_display_rows(
        {"circl": {"status": "error", "error": "HTTP 401"}},
        {"circl": "error"},
    )[0]

    assert row["display_status"] == "Error"
    assert "HTTP 401" in row["summary"]
    assert "check API credentials" in row["summary"]


def test_nrd_sources_merge_without_changing_source_class_counts():
    sources = {
        "smet_nrd": {"status": "\u2717", "score": 0, "found": False, "message": "Not found in Smet NRD"},
        "hagezi_nrd": {"status": "\u2717", "score": 0, "found": False, "message": "Not found in HaGeZi NRD"},
        "threatfox": {"status": "found", "score": 90},
    }
    classes = {"smet_nrd": "clean", "hagezi_nrd": "clean", "threatfox": "flagged"}
    counts_before = Counter(classes.values())

    rows = build_source_display_rows(sources, classes)

    merged = [row for row in rows if row["group_key"] == "nrd"]
    assert len(merged) == 1
    assert merged[0]["display_name"] == "Smet NRD, HaGeZi NRD"
    assert len(merged[0]["source_names"]) == 2
    assert Counter(classes.values()) == counts_before
    assert len(classes) == len(sources)


def test_nrd_sources_do_not_merge_when_classes_differ():
    rows = build_source_display_rows(
        {
            "smet_nrd": {"status": "found", "score": 85},
            "hagezi_nrd": {"status": "error", "error": "Timeout"},
        },
        {"smet_nrd": "flagged", "hagezi_nrd": "error"},
    )

    assert {row["display_name"] for row in rows} == {"Smet NRD", "HaGeZi NRD"}
    assert all(row["group_key"] != "nrd" for row in rows)


def test_source_rows_sort_by_class_then_score():
    rows = build_source_display_rows(
        {
            "clean-feed": {"status": "clean", "score": 0},
            "error-feed": {"status": "error", "error": "Timeout"},
            "low-feed": {"status": "\u2713", "score": 30},
            "flagged-low": {"status": "flagged", "score": 60},
            "flagged-high": {"status": "flagged", "score": 90},
        },
        {
            "clean-feed": "clean",
            "error-feed": "error",
            "low-feed": "other",
            "flagged-low": "flagged",
            "flagged-high": "flagged",
        },
    )

    assert [row["source_name"] for row in rows] == [
        "flagged-high",
        "flagged-low",
        "low-feed",
        "error-feed",
        "clean-feed",
    ]


def test_expandable_source_markup_uses_button_and_escapes_feed_values():
    html = _render_report(
        {"unsafe_feed": {"status": "found", "score": 90, "evidence": "<script>alert(1)</script>", "extra": "expand panel"}}
    )

    assert 'class="rv-source-toggle"' in html
    assert 'aria-expanded="false"' in html
    assert 'class="rv-source-detail"' in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_existing_source_count_fixture_keeps_summary_counts_and_tile():
    html = _render_report(_count_fixture_sources())
    virustotal_row = re.search(r'<tr[^>]*>.*?VirusTotal.*?</tr>', html, re.DOTALL).group(0)

    assert "1 FLAGGED" in html
    assert "7 RESPONDED" in html
    assert "2 ERRORS" in html
    assert "19 N/A" in html
    assert "1 / 7" in html
    assert "ThreatFox 90" in html
    assert 'class="rv-source-chevron-placeholder" aria-hidden="true"' in virustotal_row


def test_not_applicable_sources_render_as_wrapping_chips_with_scored_marker():
    html = _render_report(
        {
            "threatfox": {"status": "\u2796", "not_applicable": True},
            "virustotal": {"status": "\u2796", "not_applicable": True},
        }
    )
    na_section = re.search(r'<details class="rv-na".*?</details>', html, re.DOTALL).group(0)

    assert 'class="rv-na-list"' in na_section
    assert 'class="rv-na-chip"><strong>ThreatFox</strong>' in na_section
    assert 'class="rv-na-chip"><strong>VirusTotal</strong>' in na_section
    assert ">SCORED</span>" in na_section


def test_scored_chip_uses_scorer_constant_and_omits_report_only_virustotal(monkeypatch):
    monkeypatch.setitem(
        SOURCE_SCORING_MULTIPLIERS,
        "threatfox",
        SOURCE_SCORING_MULTIPLIERS["threatfox"] + 0.11,
    )
    html = _render_report(_count_fixture_sources())
    threatfox_row = re.search(r'<tr[^>]*>.*?ThreatFox.*?</tr>', html, re.DOTALL).group(0)
    virustotal_row = re.search(r'<tr[^>]*>.*?VirusTotal.*?</tr>', html, re.DOTALL).group(0)
    expected_weight = f"{SOURCE_SCORING_MULTIPLIERS['threatfox']:.2f}"

    assert f'title="Counted in threat score, weight {expected_weight}; contributes only when its score is greater than 0"' in threatfox_row
    assert ">SCORED</span>" in threatfox_row
    assert "rv-scored-chip" not in virustotal_row


def test_merged_nrd_row_has_no_scored_chip():
    html = _render_report(
        {
            "smet_nrd": {"status": "\u2717", "score": 0, "found": False, "message": "Not found in Smet NRD"},
            "hagezi_nrd": {"status": "\u2717", "score": 0, "found": False, "message": "Not found in HaGeZi NRD"},
        }
    )
    merged_row = re.search(r'<tr[^>]*>.*?Smet NRD, HaGeZi NRD.*?</tr>', html, re.DOTALL).group(0)

    assert "rv-scored-chip" not in merged_row
    assert "Scoring:</strong> not used in score" in html


def test_print_markup_keeps_source_summary_but_detail_panel_hidden():
    html = _render_report(
        {
            "threatfox": {"status": "found", "score": 90, "confidence": 100, "extra": "expand panel"},
            "unsafe_feed": {"status": "found", "score": 90, "evidence": "print detail", "extra": "expand panel"},
        },
        print_mode=True,
    )

    assert ">SCORED</span>" in html
    assert "print detail" in html
    assert 'class="rv-source-detail"' in html
    assert "rv-source-detail, .report-v2 .rv-source-detail[hidden] { display: none !important; }" in html


def test_raw_json_expand_opens_outer_panel_before_opening_tree_nodes():
    html = _render_report({"safe": {"status": "clean", "score": 0}})
    expand_handler = re.search(
        r"expandButton\.addEventListener\('click', function \(\) \{(.*?)\}\);",
        html,
        re.DOTALL,
    ).group(1)

    assert "Collapse.getOrCreateInstance(rawDataPanel, { toggle: false }).show()" in html
    assert expand_handler.index("showRawDataPanel();") < expand_handler.index("setTreeExpanded(true);")


def test_raw_json_collapse_closes_nodes_without_closing_outer_panel():
    html = _render_report({"safe": {"status": "clean", "score": 0}})
    collapse_handler = re.search(
        r"collapseButton\.addEventListener\('click', function \(\) \{(.*?)\}\);",
        html,
        re.DOTALL,
    ).group(1)

    assert "item.open = expanded" in html
    assert "setTreeExpanded(false);" in collapse_handler
    assert "rawDataPanel" not in collapse_handler


def test_raw_json_print_hides_tree_and_controls():
    html = _render_report({"safe": {"status": "clean", "score": 0}})

    assert ".report-v2 #rawJsonTree, .report-v2 .rv-raw-tools { display: none !important; }" in html
