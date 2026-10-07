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


def _render_report(
    sources,
    *,
    print_mode=False,
    domain_enrichment=None,
    detection_rules=None,
    report_fields=None,
):
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
            "domain_enrichment": domain_enrichment or {},
        },
    }
    if detection_rules is not None:
        job["result"]["detection_rules"] = detection_rules
    if report_fields:
        job["result"].update(report_fields)
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
    assert 'class="rv-source-toggle"' in virustotal_row
    assert "rv-source-chevron-placeholder" not in html


def test_virustotal_with_only_summary_fields_still_has_expandable_raw_details():
    html = _render_report(
        {
            "virustotal": {
                "status": "\u2713",
                "score": 30,
                "detections": "6/91",
                "last_analysis": "2026-10-06 12:30 UTC",
            }
        }
    )
    source_row = re.search(r'<tr[^>]*>.*?VirusTotal.*?</tr>', html, re.DOTALL).group(0)
    detail_id = re.search(r'aria-controls="([^"]+)"', source_row).group(1)
    detail_panel = re.search(
        rf'<tr class="rv-source-detail" id="{re.escape(detail_id)}" hidden>(.*?)</tr>',
        html,
        re.DOTALL,
    ).group(1)

    assert 'class="rv-source-toggle"' in source_row
    assert "Scoring:</strong> not used in score" in detail_panel
    assert "Raw status:</strong> " + "\u2713" in detail_panel
    assert "Raw score:</strong> 30" in detail_panel
    assert "detections" in detail_panel
    assert "last analysis" in detail_panel


def test_threatfox_expanded_panel_contains_raw_status_and_score():
    html = _render_report(
        {"threatfox": {"status": "found", "score": 90, "confidence": 100}}
    )
    source_row = re.search(r'<tr[^>]*>.*?ThreatFox.*?</tr>', html, re.DOTALL).group(0)
    detail_id = re.search(r'aria-controls="([^"]+)"', source_row).group(1)
    detail_panel = re.search(
        rf'<tr class="rv-source-detail" id="{re.escape(detail_id)}" hidden>(.*?)</tr>',
        html,
        re.DOTALL,
    ).group(1)

    assert "Raw status:</strong> found" in detail_panel
    assert "Raw score:</strong> 90" in detail_panel


def test_details_show_extra_fields_only_when_present():
    html = _render_report(
        {
            "threatfox": {
                "status": "found",
                "score": 90,
                "confidence": 100,
                "evidence": "<script>feed value</script>",
            },
            "bare_source": {"status": "clean", "score": 0},
        }
    )
    threatfox_row = re.search(
        r'<tr[^>]*>(?:(?!</tr>).)*?ThreatFox(?:(?!</tr>).)*?</tr>', html, re.DOTALL
    ).group(0)
    bare_row = re.search(
        r'<tr[^>]*>(?:(?!</tr>).)*?Bare Source(?:(?!</tr>).)*?</tr>', html, re.DOTALL
    ).group(0)
    threatfox_id = re.search(r'aria-controls="([^"]+)"', threatfox_row).group(1)
    bare_id = re.search(r'aria-controls="([^"]+)"', bare_row).group(1)
    threatfox_panel = re.search(
        rf'<tr class="rv-source-detail" id="{re.escape(threatfox_id)}" hidden>(.*?)</tr>', html, re.DOTALL
    ).group(1)
    bare_panel = re.search(
        rf'<tr class="rv-source-detail" id="{re.escape(bare_id)}" hidden>(.*?)</tr>', html, re.DOTALL
    ).group(1)

    assert "confidence" in threatfox_panel
    assert "&lt;script&gt;feed value&lt;/script&gt;" in threatfox_panel
    assert "<script>feed value</script>" not in threatfox_panel
    assert 'class="rv-detail-item"' not in bare_panel


def test_all_normal_rows_have_expand_buttons_and_na_chips_do_not():
    html = _render_report(
        {
            "virustotal": {"status": "\u2713", "score": 30},
            "bare_source": {"status": "clean", "score": 0},
            "na_source": {"status": "\u2796", "not_applicable": True},
        }
    )
    main_table = re.search(r'<tbody>(.*?)</tbody>', html, re.DOTALL).group(1)
    source_rows = re.findall(r'(<tr(?: class="[^"]*")?>.*?</tr>)', main_table, re.DOTALL)
    na_section = re.search(r'<details class="rv-na".*?</details>', html, re.DOTALL).group(0)

    assert source_rows
    assert all('class="rv-source-toggle"' in row for row in source_rows if "rv-source-detail" not in row)
    assert "rv-source-chevron-placeholder" not in main_table
    assert 'class="rv-source-toggle"' not in na_section
    assert "aria-controls=" not in na_section


def test_every_source_panel_starts_hidden_with_collapsed_button():
    html = _render_report(
        {
            "threatfox": {"status": "found", "score": 90},
            "virustotal": {"status": "\u2713", "score": 30},
            "na_source": {"status": "\u2796", "not_applicable": True},
        }
    )
    controls = re.findall(
        r'<button class="rv-source-toggle"[^>]*aria-expanded="([^"]+)"[^>]*aria-controls="([^"]+)"',
        html,
    )
    panels = {
        panel_id: attrs
        for panel_id, attrs in re.findall(
            r'<tr class="rv-source-detail" id="([^"]+)"([^>]*)>', html
        )
    }

    assert controls
    assert all(expanded == "false" for expanded, _ in controls)
    assert all(panel_id in panels and "hidden" in panels[panel_id] for _, panel_id in controls)
    assert len(panels) == len(controls)


def test_print_keeps_scored_chip_and_hides_expanded_source_panel():
    html = _render_report(
        {"threatfox": {"status": "found", "score": 90, "confidence": 100}},
        print_mode=True,
    )

    assert ".report-v2 .rv-source-detail, .report-v2 .rv-source-detail[hidden] { display: none !important; }" in html
    assert ">SCORED</span>" in html
    assert 'class="rv-source-detail"' in html


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


def _domain_enrichment(is_dga=True, confidence=80):
    return {
        "domain_age": {
            "creation_date": "2016-02-11T00:00:00Z",
            "age_days": 3889,
            "is_newly_registered": False,
            "risk_level": "none",
        },
        "dga_analysis": {
            "is_dga": is_dga,
            "confidence": confidence,
            "dga_family_guess": "generic_random",
            "sld": "bossbey",
            "entropy": 2.2359,
            "consonant_ratio": 0.7143,
            "dictionary_match": {"words_found": ["boss"]},
        },
    }


def test_domain_intelligence_uses_console_title_and_confidence_badge():
    html = _render_report(_count_fixture_sources(), domain_enrichment=_domain_enrichment())
    domain_card = re.search(
        r'<div class="rv-card card-print-flow">\s*<div class="rv-card-head card-header-collapsible" data-bs-toggle="collapse" data-bs-target="#domainIntelligenceCollapse".*?</div>',
        html,
        re.DOTALL,
    ).group(0)
    dga_card = re.search(
        r'<section class="rv-domain-card"><h3>DGA heuristic.*?</section>',
        html,
        re.DOTALL,
    ).group(0)

    assert '<h2 class="rv-console-title">Domain intelligence</h2>' in domain_card
    assert '.rv-card-head .rv-console-title::before { content: "// ";' in html
    assert '<span class="rv-pill rv-pill--flag">80%</span>' in dga_card
    assert "1 FLAGGED" in html and "7 RESPONDED" in html
    assert "2 ERRORS" in html and "19 N/A" in html and "1 / 7" in html


def test_domain_intelligence_uses_lowercase_labels_and_merged_entropy_row():
    html = _render_report(
        {"threatfox": {"status": "found", "score": 90}},
        domain_enrichment=_domain_enrichment(),
    )

    for label in (
        "created", "age", "newly registered", "risk level", "family guess",
        "analyzed label", "entropy", "/ consonant ratio", "dictionary words",
    ):
        assert f">{label}</span>" in html
    assert (
        'entropy</span><strong>2.2359 <span class="rv-domain-secondary-label">'
        "/ consonant ratio</span> 0.7143</strong>"
    ) in html
    assert ">Confidence</span>" not in html


def test_domain_intelligence_keeps_existing_dga_pill_conditions():
    likely_html = _render_report(
        {}, domain_enrichment=_domain_enrichment(is_dga=True, confidence=70)
    )
    weak_html = _render_report(
        {}, domain_enrichment=_domain_enrichment(is_dga=True, confidence=69)
    )
    neutral_html = _render_report(
        {}, domain_enrichment=_domain_enrichment(is_dga=False, confidence=90)
    )

    assert ">DGA likely</span>" in likely_html
    assert ">Weak signal</span>" in weak_html
    assert ">Not flagged</span>" in neutral_html
    assert 'class="rv-pill rv-pill--flag">70%</span>' in likely_html
    assert 'class="rv-pill rv-pill--error">69%</span>' in weak_html


def test_domain_intelligence_keeps_console_markup_in_print_mode():
    html = _render_report(
        _count_fixture_sources(),
        print_mode=True,
        domain_enrichment=_domain_enrichment(),
    )

    assert 'id="domainIntelligenceCollapse"' in html
    assert '<h2 class="rv-console-title">Domain intelligence</h2>' in html
    assert '<span class="rv-pill rv-pill--flag">80%</span>' in html
    assert ".report-v2 .card.card-print-flow { break-inside: auto; page-break-inside: auto; }" in html
    assert "1 FLAGGED" in html and "7 RESPONDED" in html
    assert "2 ERRORS" in html and "19 N/A" in html and "1 / 7" in html


def _render_report_with_rules(*, print_mode=False):
    return _render_report(
        _count_fixture_sources(),
        print_mode=print_mode,
        detection_rules={
            "kql": "DeviceNetworkEvents\n| where RemoteUrl has \"example.com\"",
            "sigma": "title: Example detection\nlogsource:\n  product: windows",
        },
    )


def test_detection_rules_uses_console_header_and_brackets():
    html = _render_report_with_rules()
    header = re.search(
        r'<div class="rv-card-head rv-rule-card-head">(.*?)</div>\s*<div class="collapse show" id="rulesCollapse">',
        html,
        re.DOTALL,
    ).group(1)

    assert 'class="rv-console-title" role="heading" aria-level="2">Detection Rules</span>' in header
    assert re.search(
        r'data-rule-approved-count\s+data-analysis-id="display-test">approved 0 of 2',
        header,
    )
    assert 'data-bs-toggle="collapse" data-bs-target="#rulesCollapse" aria-expanded="true"' in header
    assert "collapse-chevron" in header
    assert 'data-rule-action="zip"' in header
    assert "Export selected as ZIP" in header
    assert '.rv-card-head .rv-console-title::before { content: "// ";' in html
    assert ".rv-rule-card:has(> #rulesCollapse)::before" in html
    assert ".rv-rule-card:has(> #rulesCollapse)::after" in html


def test_detection_rule_tabs_keep_bootstrap_hooks_and_console_active_state():
    html = _render_report_with_rules()

    assert 'class="nav nav-tabs mb-0 rv-rule-tabs" id="ruleTabs" role="tablist"' in html
    assert 'class="nav-link active"' in html
    assert 'id="tab-1" data-bs-toggle="tab"' in html
    assert 'data-bs-target="#tabpane-1" type="button" role="tab"' in html
    assert 'aria-controls="tabpane-1" aria-selected="true"' in html
    assert 'id="tabpane-1" role="tabpanel" aria-labelledby="tab-1"' in html
    assert ".rv-rule-tabs.nav-tabs .nav-link.active" in html
    assert "border-bottom-color: var(--rv-cyan)" in html


def test_detection_rule_toolbar_order_status_and_action_hooks_are_preserved():
    html = _render_report_with_rules()
    toolbar = re.search(
        r'<div class="rule-copy-actions rule-export-actions no-print rv-rule-toolbar">(.*?)</div>',
        html,
        re.DOTALL,
    ).group(1)
    ordered_labels = (
        "Pending review", "Copy", "Copy format", "Approve export", "Download",
        "Mark as Deployed", "Edit",
    )

    assert [toolbar.index(label) for label in ordered_labels] == sorted(
        toolbar.index(label) for label in ordered_labels
    )
    assert toolbar.index("data-rule-status") < toolbar.index("data-rule-action=\"approve\"")
    for action in ("approve", "download", "deploy", "edit", "save", "cancel"):
        assert f'data-rule-action="{action}"' in html
    assert 'data-rule-id="rulecode-1"' in toolbar
    assert 'data-copy-format="kql"' in toolbar
    assert 'data-analysis-id="display-test"' in toolbar
    assert 'data-rule-type="kql"' in toolbar
    assert "<i class=\"bi " not in toolbar


def test_download_and_deploy_enabled_states_match_original_rule_status_logic():
    html = _render_report_with_rules()
    script = Path(__file__).resolve().parents[1].joinpath(
        "static/js/analysis.js"
    ).read_text(encoding="utf-8")

    for action in ("download", "deploy"):
        button = re.search(
            rf'<button\b[^>]*data-rule-action="{action}"[^>]*>', html
        ).group(0)
        assert re.search(r"\sdisabled(?:\s|>)", button)

    # The template starts both controls disabled. Runtime state enables each
    # only after approval or manual deployment, matching the original behavior.
    assert re.search(
        r"if\s*\(action\s*===\s*'download'\s*\|\|\s*action\s*===\s*'deploy'\)\s*"
        r"\{\s*element\.disabled\s*=\s*state\.status\s*!==\s*'approved'\s*"
        r"&&\s*state\.status\s*!==\s*'deployed';\s*\}",
        script,
    )
    assert {
        status: status not in {"approved", "deployed"}
        for status in ("pending_review", "approved", "deployed", "rejected")
    } == {
        "pending_review": True,
        "approved": False,
        "deployed": False,
        "rejected": True,
    }


def test_enabled_download_and_deploy_styles_remain_clickable():
    html = _render_report_with_rules()
    css_rules = re.findall(r"([^{}]+)\{([^{}]*)\}", html)

    enabled_selector = (
        '.rv-rule-action[data-rule-action="download"]:not(:disabled)',
        '.rv-rule-action[data-rule-action="deploy"]:not(:disabled)',
    )
    for selector in enabled_selector:
        matching_rules = [declarations for rule, declarations in css_rules if selector in rule]
        assert matching_rules
        assert any("cursor: pointer" in declarations for declarations in matching_rules)

    assert not any(
        "pointer-events: none" in declarations
        and ("rv-rule-action" in rule or "data-rule-action" in rule)
        for rule, declarations in css_rules
    )


def test_detection_rule_export_selection_and_summary_hooks_remain_in_place():
    html = _render_report_with_rules()

    assert 'class="form-check-input" type="checkbox" checked' in html
    assert 'data-rule-select' in html
    assert 'data-analysis-id="display-test"' in html
    assert 'data-rule-type="kql"' in html
    assert 'data-rule-export-status' in html
    assert 'data-analysis-id="display-test" aria-live="polite"' in html
    assert "Select at least one rule to export." in html
    assert "Approved ' + approvedCount + ' of ' + selected.length +" in Path(
        __file__
    ).parents[1].joinpath("static/js/analysis.js").read_text(encoding="utf-8")
    assert 'id="ruleTabContent"' in html
    assert 'id="rulecode-1" data-rule-display' in html
    assert 'data-rule-editor' in html
    assert 'data-rule-validation-errors' in html


def test_detection_rule_code_block_and_print_rules_remain_console_safe():
    html = _render_report_with_rules(print_mode=True)

    assert 'class="rv-card rv-rule-card card-print-flow mb-4"' in html
    assert ".rv-rule-card .rule-tab-content pre, .report-v2 .rv-rule-card .rule-wrapper > pre" in html
    assert "background: #02060e" in html
    assert "border-radius: 0" in html
    assert ".report-v2 .no-print { display: none !important; }" in html
    assert ".report-v2 .card.card-print-flow { break-inside: auto; page-break-inside: auto; }" in html
    assert "1 FLAGGED" in html and "7 RESPONDED" in html
    assert "2 ERRORS" in html and "19 N/A" in html and "1 / 7" in html


def test_rule_approval_dialog_has_accessible_console_markup_and_print_rule():
    html = _render_report_with_rules(print_mode=True)
    dialog = re.search(r'<dialog id="rvRuleApprovalDialog".*?</dialog>', html, re.DOTALL)
    assert dialog
    markup = dialog.group(0)

    assert 'role="dialog" aria-modal="true" aria-labelledby="rvRuleApprovalTitle"' in markup
    assert 'id="rvRuleApprovalTitle" data-rule-approval-title' in markup
    assert 'for="rvRuleApprovalReviewer">Reviewer name</label>' in markup
    assert 'value="unknown"' in markup
    assert ">Cancel</button>" in markup and ">Approve</button>" in markup
    assert ".report-v2 .rv-rule-approval-dialog { display: none !important; }" in html
    assert "1 FLAGGED" in html and "7 RESPONDED" in html
    assert "2 ERRORS" in html and "19 N/A" in html and "1 / 7" in html


def test_cancelled_rule_approval_does_not_call_approval_api_and_prompt_fallback_exists():
    script = Path(__file__).resolve().parents[1].joinpath(
        "static/js/analysis.js"
    ).read_text(encoding="utf-8")
    click_handler = re.search(
        r"button\.addEventListener\('click', async function \(\) \{(.*?)\n\s*\}\);",
        script,
        re.DOTALL,
    ).group(1)

    assert re.search(
        r"var approvedBy = await requestRuleApproval\(button, button\.getAttribute\('data-rule-type'\)\);\s*"
        r"if \(approvedBy !== null\) approveRuleArtifact\(button, approvedBy\);",
        click_handler,
    )
    assert "window.prompt('Reviewer name for this rule export approval:', 'unknown')" in script
    assert "if (!dialog || typeof dialog.showModal !== 'function')" in script


def test_recommendations_card_console_header_retry_hooks_and_corners():
    html = _render_report(
        _count_fixture_sources(),
        report_fields={"recommendations_rule_based": ["Keep watching the IOC."]},
    )

    assert 'class="rv-console-title">Recommendations</h2>' in html
    assert '<span class="rv-muted rv-recommendations-subtitle">AI vs rule-based</span>' in html
    assert re.search(
        r'<button(?=[^>]*disabled)(?=[^>]*title="Available after C4")'
        r'(?=[^>]*class="[^"]*rv-retry-ai")[^>]*>Retry AI analysis</button>',
        html,
    )
    assert ".rv-recommendations-card::before" in html
    assert ".rv-recommendations-card::after" in html
    assert '.rv-card-head .rv-console-title::before { content: "// ";' in html


def test_recommendations_ai_badge_maps_report_states():
    expected = {
        "complete": ('rv-ai-state--complete">COMPLETE',),
        "running": ('rv-ai-state--running">RUNNING',),
        "failed": ('rv-ai-state--unavailable">UNAVAILABLE',),
        "unavailable": ('rv-ai-state--unavailable">UNAVAILABLE',),
        "disabled": ('rv-ai-state--unavailable">UNAVAILABLE',),
    }
    for status, needles in expected.items():
        html = _render_report(
            _count_fixture_sources(),
            report_fields={
                "ai_status": status,
                "recommendations_rule_based": ["Keep watching the IOC."],
            },
        )
        assert needles[0] in html

    missing = _render_report(
        _count_fixture_sources(),
        report_fields={"recommendations_rule_based": ["Keep watching the IOC."]},
    )
    assert 'rv-ai-state--unavailable">UNAVAILABLE' in missing
    assert "AI status not recorded for this report" in missing


def test_recommendations_warning_only_shows_recorded_reason_and_provider():
    rule_recommendations = ["Keep watching the IOC."]
    absent = _render_report(
        _count_fixture_sources(),
        report_fields={
            "ai_status": "failed",
            "recommendations_rule_based": rule_recommendations,
        },
    )
    absent_panel = re.search(
        r'<section class="rv-col" aria-labelledby="aiAnalysisTitle">(.*?)</section>',
        absent,
        re.DOTALL,
    ).group(1)
    assert "AI analysis failed for this report." in absent_panel
    assert "Reason:" not in absent_panel
    assert "Provider:" not in absent_panel

    provided = _render_report(
        _count_fixture_sources(),
        report_fields={
            "ai_status": "failed",
            "ai_error": "<network timeout>",
            "llm_analysis": {"provider": "ollama"},
            "recommendations_rule_based": rule_recommendations,
        },
    )
    provided_panel = re.search(
        r'<section class="rv-col" aria-labelledby="aiAnalysisTitle">(.*?)</section>',
        provided,
        re.DOTALL,
    ).group(1)
    assert "<b>Reason:</b> &lt;network timeout&gt;" in provided_panel
    assert "<b>Provider:</b> ollama" in provided_panel
    assert "<network timeout>" not in provided_panel


def test_recommendations_rule_based_badge_footer_note_and_print_rules():
    absent_ai = _render_report(
        _count_fixture_sources(),
        print_mode=True,
        report_fields={"recommendations_rule_based": ["Keep watching the IOC."]},
    )
    assert '<span class="rv-pill rv-always-on">ALWAYS ON</span>' in absent_ai
    assert '<span class="rv-rule-based-marker" aria-hidden="true">[::]</span>' in absent_ai
    assert "filled automatically once AI analysis is available" in absent_ai
    assert 'class="rv-card card-print-flow rv-recommendations-card"' in absent_ai
    assert ".report-v2 .card.card-print-flow { break-inside: auto; page-break-inside: auto; }" in absent_ai
    assert "1 FLAGGED" in absent_ai and "7 RESPONDED" in absent_ai
    assert "2 ERRORS" in absent_ai and "19 N/A" in absent_ai and "1 / 7" in absent_ai

    with_ai = _render_report(
        _count_fixture_sources(),
        report_fields={
            "ai_status": "complete",
            "llm_analysis": {"recommendations": ["Review source findings."]},
            "recommendations_rule_based": ["Keep watching the IOC."],
        },
    )
    assert "Review source findings." in with_ai
    assert "filled automatically once AI analysis is available" not in with_ai


def test_scored_chip_uses_scorer_constant_and_omits_report_only_virustotal(monkeypatch):
    monkeypatch.setitem(
        SOURCE_SCORING_MULTIPLIERS,
        "threatfox",
        SOURCE_SCORING_MULTIPLIERS["threatfox"] + 0.11,
    )
    html = _render_report(_count_fixture_sources())
    threatfox_row = re.search(
        r'<tr[^>]*>(?:(?!</tr>).)*?ThreatFox(?:(?!</tr>).)*?</tr>', html, re.DOTALL
    ).group(0)
    virustotal_row = re.search(
        r'<tr[^>]*>(?:(?!</tr>).)*?VirusTotal(?:(?!</tr>).)*?</tr>', html, re.DOTALL
    ).group(0)
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
