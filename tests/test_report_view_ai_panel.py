import re
from pathlib import Path

from src.tools.ioc_investigator import IOCInvestigator

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.requests import Request


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _request(role="admin", print_mode=False):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/reports/job-1/html",
        "raw_path": b"/api/reports/job-1/html",
        "query_string": b"print=1" if print_mode else b"",
        "headers": [],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
    }
    request = Request(scope)
    request.state.user = {"role": role}
    return request


def _source_fixture():
    sources = {"flagged-source": {"status": "flagged", "score": 90}}
    sources.update(
        {f"responded-{index}": {"status": "clean", "score": 0} for index in range(6)}
    )
    sources.update(
        {
            f"error-{index}": {"status": "error", "error": "HTTP 401"}
            for index in range(2)
        }
    )
    sources.update(
        {
            f"na-{index}": {"status": "not_applicable", "not_applicable": True}
            for index in range(19)
        }
    )
    return sources


def _result(**updates):
    result = {
        "ioc": "example.com",
        "ioc_type": "domain",
        "verdict": "suspicious",
        "threat_score": 61,
        "sources": _source_fixture(),
        "recommendations": ["Fallback rule recommendation"],
        "recommendations_rule_based": ["Fallback rule recommendation"],
        "recommendations_source": "rule_based",
        "detection_rules": {"kql": "DeviceEvents | take 10"},
        "domain_enrichment": {
            "domain_age": {"creation_date": "2022-01-01", "age_days": 1000},
            "dga_analysis": {"is_dga": True, "confidence": 80},
        },
    }
    result.update(updates)
    return result

def _legacy_result(**updates):
    result = _result(**updates)
    result.pop("ai_status", None)
    result.pop("ai_error", None)
    result.pop("recommendations_rule_based", None)
    return result

def _render(result, role="admin", analysis_type="ioc", print_mode=False, created_at="2026-10-05T06:50:00+00:00", completed_at="2026-10-05T06:51:00+00:00"):
    job = {
        "id": "job-1",
        "analysis_type": analysis_type,
        "status": "completed",
        "created_at": created_at,
        "completed_at": completed_at,
        "result": result,
    }
    environment = Environment(
        loader=FileSystemLoader(str(PROJECT_ROOT / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return environment.get_template("report_view.html").render(
        request=_request(role, print_mode), job=job
    )


def _panel(html, panel_id):
    start = html.index(f'id="{panel_id}"')
    start = html.rfind("<section", 0, start)
    end = html.index("</section>", start) + len("</section>")
    return html[start:end]


def test_complete_ai_analysis_renders_llm_content_without_failure_state():
    html = _render(
        _result(
            ai_status="complete",
            llm_analysis={
                "verdict": "suspicious",
                "analysis": "LLM_ANALYSIS_SENTINEL",
                "recommendations": ["LLM_RECOMMENDATION_SENTINEL"],
                "hallucination_warning": "LLM_WARNING_SENTINEL",
            },
        )
    )

    panel = _panel(html, "aiAnalysisTitle")
    assert "LLM_ANALYSIS_SENTINEL" in panel
    assert "LLM_RECOMMENDATION_SENTINEL" in panel
    assert "LLM_WARNING_SENTINEL" in panel
    assert "AI analysis failed" not in panel
    assert "disabled in configuration" not in panel
    assert 'class="rv-legacy-ai"' not in html


def test_failed_ai_error_is_html_escaped():
    html = _render(
        _result(ai_status="failed", ai_error="<script>alert(1)</script>")
    )
    panel = _panel(html, "aiAnalysisTitle")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in panel
    assert "<script>alert(1)</script>" not in panel


def test_failed_ai_without_error_shows_restricted_details():
    panel = _panel(_render(_result(ai_status="failed")), "aiAnalysisTitle")

    assert "details restricted" in panel


def test_disabled_ai_status_is_explained():
    panel = _panel(_render(_result(ai_status="disabled")), "aiAnalysisTitle")

    assert "AI analysis is disabled in configuration" in panel


def test_missing_ai_status_with_rule_based_list_shows_both_columns_and_not_recorded():
    html = _render(_result())
    panel = _panel(html, "aiAnalysisTitle")

    assert 'id="aiAnalysisTitle"' in html
    assert 'id="ruleBasedTitle"' in html
    assert "AI status not recorded for this report" in panel
    assert "AI analysis failed" not in panel


def test_legacy_report_keeps_single_recommendations_list():
    result = _result()
    result.pop("recommendations_rule_based")
    result.pop("ai_status", None)
    html = _render(result)

    assert 'id="aiAnalysisTitle"' not in html
    assert 'id="ruleBasedTitle"' not in html
    assert ">AI analysis<" not in html
    assert ">Rule-based playbook<" not in html
    assert "Fallback rule recommendation" in html


def test_both_recommendation_columns_and_disabled_retry_always_render():
    html = _render(_result())

    assert 'id="aiAnalysisTitle"' in html
    assert 'id="ruleBasedTitle"' in html
    assert "Retry AI analysis" in html
    assert re.search(
        r'<button(?=[^>]*disabled)(?=[^>]*title="Available after C4")[^>]*>Retry AI analysis</button>',
        html,
    )


def test_source_count_pills_use_sources_mapping():
    html = _render(_result())

    assert "1 FLAGGED" in html
    assert "7 RESPONDED" in html
    assert "2 ERRORS" in html
    assert "19 N/A" in html


def test_report_source_classification_matches_reported_source_behaviors():
    # Minimal regression fixture based on the source behaviors described for the real report; its JSON artifact was unavailable.
    # Keep only fields used by source classification and row rendering.
    sources = {
        "threatfox": {"status": "found", "score": 90},
        "virustotal": {"status": "\u2713", "score": 30},
        "circl": {"status": "error", "score": 0, "error": "HTTP 401"},
        "misp_circl_feed_osint": {"status": "unavailable", "score": 0, "feed_status": "unavailable"},
    }
    sources.update({f"responded-{index}": {"status": "clean", "score": 0} for index in range(5)})
    sources.update({f"na-{index}": {"status": "\u2796", "not_applicable": True} for index in range(19)})
    html = _render(_result(sources=sources))

    assert "1 FLAGGED" in html
    assert "7 RESPONDED" in html
    assert "2 ERRORS" in html
    assert "19 N/A" in html
    assert "1 / 7" in html
    assert re.search(r"<strong>Threatfox</strong>.*?badge-danger.*?Flagged", html, re.DOTALL)
    assert re.search(r"<strong>Circl</strong>.*?badge-warning.*?Error", html, re.DOTALL)
    assert re.search(r"<strong>Misp_circl_feed_osint</strong>.*?badge-warning.*?Error", html, re.DOTALL)


def test_ioc_investigator_recommendations_render_without_leading_non_ascii():
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    recommendations = []
    for verdict in ("MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"):
        recommendations.extend(investigator._generate_recommendations(verdict, {}))
    # The newly registered recommendation is inserted by analysis orchestration,
    # not _generate_recommendations, so include that emitted value directly.
    recommendations.append("\U0001F195 Domain is newly registered (<30 days) - high risk indicator")
    original = list(recommendations)
    html = _render(_result(recommendations_rule_based=recommendations))
    panel = _panel(html, "ruleBasedTitle")
    rendered_items = re.findall(r"<li>(.*?)</li>", panel, re.DOTALL)

    assert rendered_items
    assert all(not re.match(r"\s*[^\x00-\x7f]", item) for item in rendered_items)
    assert recommendations == original


def test_copy_json_feedback_resets_after_success_or_failure():
    template = (PROJECT_ROOT / "templates" / "report_view.html").read_text(encoding="utf-8")
    handler = template.split("var copyJsonButton = document.getElementById('cp');", 1)[1].split("{% endif %}", 1)[0]

    assert "copyJsonResetTimer" in handler
    assert "window.setTimeout" in handler
    assert "}, 1500);" in handler
    assert "copyJsonButton.textContent = 'Copy JSON';" in handler
    assert "showCopyStatus('Copy blocked')" in handler
    assert "showCopyStatus('Copied')" in handler


def test_report_timestamps_and_same_day_duration_are_print_safe():
    html = _render(
        _result(),
        created_at="2026-10-05T06:50:42.123456+00:00",
        completed_at="2026-10-05T06:52:11.987654+00:00",
    )
    assert "2026-10-05 06:50:42 UTC" in html
    assert "2026-10-05 06:52:11 UTC" in html
    assert "1m 29s" in html
    hero_meta = html.split('<div class="rv-meta">', 1)[1].split('</div>', 1)[0]
    assert "06:50:42.123456+00:00" not in hero_meta


def test_report_duration_is_na_across_dates_or_without_completion():
    cross_midnight = _render(
        _result(),
        created_at="2026-10-05T23:59:42+00:00",
        completed_at="2026-10-06T00:01:11+00:00",
    )
    no_completion = _render(
        _result(), created_at="2026-10-05T06:50:42+00:00", completed_at=""
    )
    assert re.search(r"DURATION\s*<strong>N/A</strong>", cross_midnight)
    assert re.search(r"DURATION\s*<strong>N/A</strong>", no_completion)

def test_rule_recommendation_leading_emoji_is_removed_at_render_time():
    recommendations = ["\U0001F6A8 Block this indicator immediately"]
    result = _result(recommendations_rule_based=recommendations)
    html = _render(result)
    panel = _panel(html, "ruleBasedTitle")

    assert "Block this indicator immediately" in panel
    assert "\U0001F6A8" not in panel
    assert result["recommendations_rule_based"] == recommendations


def test_rendered_report_contains_no_emoji_codepoints():
    html = _render(
        _result(
            ai_status="failed",
            ai_error="provider unavailable",
            recommendations_rule_based=["\U0001F6A8 Block this indicator"],
        )
    )

    assert not any(
        0x1F300 <= ord(character) <= 0x1FAFF
        or 0x2600 <= ord(character) <= 0x27BF
        for character in html
    )


def test_raw_json_script_payload_escapes_closing_script_from_data():
    html = _render(_result(ai_error="</script><script>alert(1)</script>"))
    payload = html.split("var resultData = ", 1)[1].split(";", 1)[0]

    assert "</script>" not in payload
    assert "\\u003c/script\\u003e" in payload



def test_legacy_file_report_renders_standalone_ai_analysis():
    html = _render(
        _legacy_result(
            file_info={"filename": "sample-binary.bin"},
            llm_analysis={
                "verdict": "suspicious",
                "analysis": "FILE_AI_ANALYSIS_SENTINEL",
            },
        ),
        analysis_type="file",
    )

    assert "FILE_AI_ANALYSIS_SENTINEL" in html
    assert "sample-binary.bin" in html
    assert 'id="aiAnalysisTitle"' not in html


def test_legacy_email_report_renders_standalone_ai_analysis():
    html = _render(
        _legacy_result(
            email_data={"subject": "Quarterly invoice review"},
            llm_analysis={
                "verdict": "suspicious",
                "analysis": "EMAIL_AI_ANALYSIS_SENTINEL",
            },
        ),
        analysis_type="email",
    )

    assert "EMAIL_AI_ANALYSIS_SENTINEL" in html
    assert "Quarterly invoice review" in html
    assert 'id="aiAnalysisTitle"' not in html


def test_legacy_ioc_renders_ai_card_without_two_column_heading():
    html = _render(
        _legacy_result(
            recommendations=["Legacy IOC recommendation"],
            llm_analysis={
                "verdict": "suspicious",
                "analysis": "LEGACY_IOC_AI_ANALYSIS_SENTINEL",
                "recommendations": ["Legacy AI recommendation"],
            },
        )
    )

    assert "LEGACY_IOC_AI_ANALYSIS_SENTINEL" in html
    assert "Legacy AI recommendation" in html
    assert ">AI analysis<" not in html
    assert 'id="aiAnalysisTitle"' not in html


def test_file_and_email_filenames_and_subjects_render_in_hero():
    file_html = _render(
        _legacy_result(file_info={"filename": "hero-sample.exe"}),
        analysis_type="file",
    )
    email_html = _render(
        _legacy_result(email_data={"subject": "Hero subject sentinel"}),
        analysis_type="email",
    )

    assert "FILE hero-sample.exe" in file_html
    assert "SUBJECT Hero subject sentinel" in email_html


def test_legacy_llm_note_and_error_are_not_emitted_raw():
    html = _render(
        _legacy_result(
            llm_analysis={
                "analysis": "Visible analysis",
                "note": "LLM_NOTE_MUST_NOT_APPEAR",
                "error": "LLM_ERROR_MUST_NOT_APPEAR",
            },
        ),
    )

    assert "Visible analysis" in html
    assert "LLM_NOTE_MUST_NOT_APPEAR" not in html
    assert "LLM_ERROR_MUST_NOT_APPEAR" not in html


def test_print_mode_keeps_raw_json_and_columns_without_script_result_payload():
    html = _render(
        _result(
            ai_status="complete",
            llm_analysis={
                "analysis": "PRINT_SCRIPT_SECRET_SENTINEL",
                "recommendations": ["Print recommendation"],
            },
        ),
        print_mode=True,
    )

    assert 'id="rawJsonPre"' in html
    assert 'class="rv-raw-tools no-print"' in html
    assert ".report-v2 .no-print { display: none !important; }" in html
    assert 'id="aiAnalysisTitle"' in html
    assert 'id="ruleBasedTitle"' in html
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.DOTALL)
    assert scripts
    assert all("PRINT_SCRIPT_SECRET_SENTINEL" not in script for script in scripts)
    assert "var resultData =" not in html
    assert "var exportData =" not in html


def test_source_status_unicode_symbols_need_no_auxiliary_fields():
    html = _render(
        _result(
            sources={
                "na-symbol": {"status": "\u2796"},
                "error-symbol": {"status": "\u26a0"},
                "clean-symbol": {"status": "\u2717"},
            }
        )
    )

    assert "1 N/A" in html
    assert "Error" in html
    assert "Clean" in html
    na_details = html.split('<details class="rv-na"', 1)[1].split("</details>", 1)[0]
    assert "Na-Symbol" in na_details

def test_preserved_dom_contracts():
    html = _render(
        _result(
            ai_status="complete",
            llm_analysis={
                "verdict": "suspicious",
                "analysis": "Preserved LLM analysis fixture.",
                "recommendations": ["Review the source reports."],
            },
        )
    )

    for element_id in (
        "reportExportDropdown",
        "btnExportReportJson",
        "reportPrintDropdown",
        "rawJsonPre",
        "rawDataCollapse",
        "ruleTabs",
    ):
        assert f'id="{element_id}"' in html
    for attribute in (
        "data-rule-select",
        "data-rule-status",
        "data-rule-display",
        "data-rule-editor",
        "data-analysis-id",
        "data-rule-type",
        "data-rule-id",
        "data-copy-format",
    ):
        assert attribute in html
    for action in ("zip", "approve", "download", "deploy", "edit", "save", "cancel"):
        assert f'data-rule-action="{action}"' in html
    assert len(re.findall(r'id="rawJsonPre"', html)) == 1
    assert len(re.findall(r'id="rawDataCollapse"', html)) == 1
    assert re.search(r'<canvas[^>]*id="scoreGauge"', html)
