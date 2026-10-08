from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


TEMPLATE = Path(__file__).parents[1] / "templates" / "agent_chat.html"


def _template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def _function_source(source: str, name: str) -> str:
    marker = f"function {name}("
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"Unclosed function: {name}")


def _run_javascript(functions: list[str], expression: str) -> str:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required to execute the template helper functions")
    script = "\n".join(functions) + f"\nprocess.stdout.write(JSON.stringify({expression}));"
    result = subprocess.run(
        [node, "-e", script],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def test_phase_cards_are_removed_before_new_phase_and_on_terminal_events():
    source = _template()
    clear = _function_source(source, "clearPhaseIndicators")
    add_phase = _function_source(source, "addPhaseIndicator")
    handler = _function_source(source, "handleWSMessage")

    assert "querySelectorAll('.phase-indicator')" in clear
    assert "card.remove()" in clear
    assert "clearPhaseIndicators();" in add_phase
    for terminal_case in ("completed", "failed", "cancelled"):
        case_start = handler.index(f"case '{terminal_case}':")
        assert "clearPhaseIndicators();" in handler[case_start : case_start + 250]


def test_completed_summary_prefers_valid_event_counts_and_converts_numbers():
    source = _template()
    summary = _function_source(source, "addInvestigationSummary")
    converter = _function_source(source, "toNonnegativeInteger")

    assert "toNonnegativeInteger(msg.steps)" in summary
    assert "eventSteps === null ? toNonnegativeInteger(currentStep) : eventSteps" in summary
    assert "toNonnegativeInteger(msg.findings_count)" in summary
    assert "Number(value)" in converter


def test_scoring_summary_counts_only_flagged_and_clean_and_is_bilingual():
    source = _template()
    coverage = _function_source(source, "getScoringCoverage")
    summary = _function_source(source, "scoringSummaryText")
    evidence_card = _function_source(source, "renderEvidenceCard")
    bubble = _function_source(source, "addBubble")

    assert "source.state === 'flagged' || source.state === 'clean'" in coverage
    assert "total: scoringSources.length" in coverage
    assert "getScoringCoverage(evidence)" in summary
    assert "Number(evidence.threat_score)" in summary
    assert "getScoringCoverage(evidence)" in evidence_card
    assert "scoreLine.textContent = scoreSummary" in bubble
    assert "if (evidence && verdict && safeSource && safeSource.tool === 'investigate_ioc')" in bubble
    assert "sources responded" in summary
    assert "\\u0e08\\u0e32\\u0e01" in summary

    evidence = {
        "verdict": "CLEAN",
        "threat_score": "0",
        "scoring_sources": [
            {"state": "flagged"},
            {"state": "clean"},
            {"state": "clean"},
            {"state": "clean"},
            {"state": "clean"},
            {"state": "unavailable"},
        ],
    }
    missing_evidence = {
        **evidence,
        "scoring_sources": evidence["scoring_sources"][:-1] + [{"state": "missing"}],
    }
    js = [
        _function_source(source, "getScoringCoverage"),
        _function_source(source, "scoringSummaryText"),
    ]
    output = json.loads(
        _run_javascript(
            js,
            "[scoringSummaryText(" + json.dumps(evidence) + ", 'en'), "
            + "scoringSummaryText(" + json.dumps(missing_evidence) + ", 'th')]",
        )
    )
    assert output == [
        "CLEAN \u00b7 0/100 \u00b7 5 of 6 sources responded",
        "CLEAN \u00b7 0/100 \u00b7 5 \u0e08\u0e32\u0e01 6 \u0e41\u0e2b\u0e25\u0e48\u0e07\u0e15\u0e2d\u0e1a\u0e01\u0e25\u0e31\u0e1a",
    ]


def test_conflicting_verdict_label_is_removed_only_from_visible_answer():
    source = _template()
    sanitizer = _function_source(source, "visibleAgentAnswer")
    bubble = _function_source(source, "addBubble")

    assert "visibleAgentAnswer(text)" in bubble
    assert "renderMarkdown(visibleAnswer)" in bubble
    assert "VERDICT\\s*:" in sanitizer
    output = json.loads(
        _run_javascript(
            [sanitizer],
            "visibleAgentAnswer('VERDICT: MALICIOUS\\nSummary stays visible.\\nverdict: UNKNOWN')",
        )
    )
    assert output == "Summary stays visible.\n"


def test_missing_visible_output_is_hidden_without_visibility_claim():
    source = _template()
    tool_result = _function_source(source, "addToolResult")

    assert "if (hasPreview)" in tool_result
    assert "No output is available under this view's visibility policy" not in tool_result


def test_new_dynamic_display_paths_use_text_content_not_inner_html():
    source = _template()
    scoring = _function_source(source, "scoringSummaryText")
    step_label = _function_source(source, "formatStepLabel")
    refetch = _function_source(source, "refetchCompletedSession")
    session_list = _function_source(source, "renderSessionList")
    bubble = _function_source(source, "addBubble")

    assert "innerHTML" not in scoring
    assert "innerHTML" not in step_label
    assert "innerHTML" not in refetch
    assert "label.textContent = sessionTypeLabel" in session_list
    assert "stepLabel.textContent = formatStepLabel" in _function_source(source, "addToolCall")
    assert "scoreLine.textContent = scoreSummary" in bubble


def test_connected_is_rendered_once_and_progress_has_no_ratio_bar():
    source = _template()
    progress = _function_source(source, "updateProgress")

    assert source.count('id="connectionStatus"') == 1
    assert 'id="agentStatusAgent" class="d-none" aria-hidden="true"' in source
    assert "getElementById('agentStatusAgent')" not in source
    assert 'id="stepProgressBar"' not in source
    assert "stepCounter').textContent = formatStepLabel" in progress
    assert "step / max" not in progress
    assert "width" not in progress
    assert ".live-tool-indicator {" in source
    assert "width: 100%;" in source[source.index(".live-tool-indicator {") : source.index(".live-tool-indicator.d-none")]


def test_completed_suggestion_refetch_warns_and_retries_once():
    source = _template()
    handler = _function_source(source, "handleWSMessage")
    refetch = _function_source(source, "refetchCompletedSession")

    assert "refetchCompletedSession(sessionId, 0)" in handler
    assert "console.warn(" in refetch
    assert "data.status === 'completed' && suggestions.length > 0" in refetch
    assert "attempt < 1" in refetch
    assert "}, 1000);" in refetch


def test_sidebar_appends_session_type_and_keeps_full_goal_tooltip():
    source = _template()
    session_list = _function_source(source, "renderSessionList")

    assert "sessionTypeLabel ? String(goal) + ' · ' + sessionTypeLabel" in session_list
    assert "button.title = String(goal);" in session_list
    assert "Playbook" in session_list
    assert "Agent" in session_list
    assert "\\u0e40" in session_list
