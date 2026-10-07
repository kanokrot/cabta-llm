from __future__ import annotations

from pathlib import Path

import pytest

from src.agent.agent_response_parsing import (
    extract_deterministic_verdict,
    sanitize_unscored_answer,
)


@pytest.mark.parametrize(
    ("tool", "verdict"),
    [
        ("investigate_ioc", "MALICIOUS"),
        ("analyze_malware", "SUSPICIOUS"),
        ("analyze_email", "CLEAN"),
    ],
)
def test_whitelisted_scoring_tool_verdict_is_authoritative(tool, verdict):
    findings = [{"type": "tool_result", "tool": tool, "result": {"verdict": verdict}}]

    assert extract_deterministic_verdict(findings) == verdict


def test_recent_malware_samples_cannot_supply_verdict_and_llm_token_is_removed():
    findings = [
        {
            "type": "tool_result",
            "tool": "threat_intel_tools.recent_malware_samples",
            "result": {
                "verdict": "MALICIOUS",
                "signature": "Mirai",
                "tags": ["Mirai"],
            },
        }
    ]
    answer = "Recent sample matched Mirai. Verdict: MALICIOUS."

    assert extract_deterministic_verdict(findings) is None
    sanitized = sanitize_unscored_answer(answer, "\u0e0a\u0e48\u0e27\u0e22\u0e2d\u0e30\u0e44\u0e23\u0e44\u0e14\u0e49\u0e1a\u0e49\u0e32\u0e07")
    assert "Verdict: MALICIOUS" not in sanitized
    assert sanitized.endswith(
        '\u0e44\u0e21\u0e48\u0e21\u0e35\u0e1c\u0e25\u0e1b\u0e23\u0e30\u0e40\u0e21\u0e34\u0e19\u0e08\u0e32\u0e01 scoring engine \u2014 \u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e19\u0e35\u0e49\u0e40\u0e1b\u0e47\u0e19\u0e2a\u0e23\u0e38\u0e1b\u0e02\u0e2d\u0e07 LLM \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48 verdict'
    )


def test_zero_ioc_extraction_and_llm_clean_label_do_not_create_verdict():
    findings = [
        {
            "type": "tool_result",
            "tool": "extract_iocs",
            "result": {"iocs": {"all_iocs": [], "total": 0}, "verdict": "CLEAN"},
        }
    ]

    assert extract_deterministic_verdict(findings) is None
    assert "Verdict: CLEAN" not in sanitize_unscored_answer(
        "No IOC found. Verdict: CLEAN", "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35"
    )


def test_unscored_unknown_verdict_token_is_removed():
    sanitized = sanitize_unscored_answer(
        "Investigation ended. Verdict: UNKNOWN", "hello there"
    )

    assert "Verdict: UNKNOWN" not in sanitized
    assert sanitized.endswith(
        "No scoring-engine result \u2014 this is an LLM summary, not a verdict."
    )


def test_non_whitelisted_verdict_is_ignored_even_when_it_is_latest():
    findings = [
        {"type": "tool_result", "tool": "investigate_ioc", "result": {"verdict": "CLEAN"}},
        {"type": "tool_result", "tool": "sandbox.scan", "result": {"verdict": "MALICIOUS"}},
    ]

    assert extract_deterministic_verdict(findings) == "CLEAN"


@pytest.mark.parametrize(
    ("goal", "notice"),
    [
        ("hello", "No scoring-engine result \u2014 this is an LLM summary, not a verdict."),
        ("สวัสดี", "ไม่มีผลประเมินจาก scoring engine — ข้อความนี้เป็นสรุปของ LLM ไม่ใช่ verdict"),
    ],
)
def test_unscored_answer_uses_notice_language_from_goal(goal, notice):
    assert sanitize_unscored_answer("Verdict: SUSPICIOUS", goal) == notice


def test_agent_loop_and_bubble_use_only_scored_verdict():
    root = Path(__file__).parents[1]
    agent_loop = (root / "src" / "agent" / "agent_loop.py").read_text(encoding="utf-8")
    template = (root / "templates" / "agent_chat.html").read_text(encoding="utf-8")
    bubble = template.split("function addBubble(text, type, trustedHtml = false, verdictOverride = null)", 1)[1].split(
        "function addPhaseIndicator", 1
    )[0]

    assert "verdict = extract_deterministic_verdict(state.findings)" in agent_loop
    assert "decision['verdict'] = verdict" in agent_loop
    assert 'extract_verdict(raw)' not in agent_loop
    assert "var verdict = normalizeVerdict(verdictOverride);" in bubble
    assert "detectVerdict(text)" not in bubble
