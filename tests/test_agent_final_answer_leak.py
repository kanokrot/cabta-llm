from __future__ import annotations

from pathlib import Path

from src.agent.agent_response_parsing import (
    build_final_answer_fallback,
    extract_deterministic_verdict,
    sanitize_final_answer,
)


_LEAKED_TOOL_TEMPLATE = (
    "[CLEAN] <|tool_call>call... osint_tools.whois_lookup"
    "{target:<|\"|>1.2.3.4<|\"|>}<tool_call|>"
)


def _scoring_findings(verdict: str = "CLEAN") -> list[dict]:
    names = (
        "feodotracker", "c2_trackers", "spamhaus", "sslblacklist",
        "tor_exit_nodes", "threatfox",
    )
    sources = {name: {"status": "✓", "score": 0} for name in names[:-1]}
    sources[names[-1]] = {"status": "⚠", "score": 0}
    return [{
        "type": "tool_result",
        "tool": "investigate_ioc",
        "step": 0,
        "result": {
            "ioc": "1.2.3.4",
            "ioc_type": "ipv4",
            "threat_score": 0,
            "verdict": verdict,
            "sources": sources,
            "coverage": {},
        },
    }]


def test_scored_tool_call_template_uses_scoring_fallback():
    answer = sanitize_final_answer(
        _LEAKED_TOOL_TEMPLATE, _scoring_findings(), "Investigate 1.2.3.4",
    )

    assert "CLEAN" in answer
    assert "0/100" in answer
    assert "1.2.3.4" in answer
    assert "5 of 6 sources responded" in answer
    assert "No readable model summary was provided" in answer
    assert "<|" not in answer
    assert "tool_call" not in answer


def test_unscored_tool_call_template_uses_neutral_notice():
    answer = sanitize_final_answer(_LEAKED_TOOL_TEMPLATE, [], "hello")

    assert answer == "The model did not provide a readable answer."
    assert "Verdict" not in answer
    assert "CLEAN" not in answer


def test_regular_answer_is_unchanged():
    answer = "The available sources found no matching activity for this indicator."

    assert sanitize_final_answer(answer, _scoring_findings(), "Investigate 1.2.3.4") == answer


def test_regular_answer_with_bracketed_verdict_text_is_unchanged():
    answer = "The report includes the literal label [CLEAN] as quoted input text."

    assert sanitize_final_answer(answer, _scoring_findings(), "Investigate 1.2.3.4") == answer


def test_tool_call_template_is_removed_while_real_summary_is_kept():
    answer = (
        "The investigation found no matching activity across the available sources. "
        + _LEAKED_TOOL_TEMPLATE
    )

    cleaned = sanitize_final_answer(answer, _scoring_findings(), "Investigate 1.2.3.4")

    assert cleaned == "The investigation found no matching activity across the available sources."
    assert "<|" not in cleaned


def test_scoring_fallback_uses_thai_goal_language():
    answer = sanitize_final_answer(
        _LEAKED_TOOL_TEMPLATE,
        _scoring_findings(),
        "ตรวจสอบ 1.2.3.4",
    )

    assert "ผล scoring:" in answer
    assert "5 จาก 6 แหล่งตอบกลับ" in answer
    assert "โมเดลไม่ได้ส่งข้อความสรุปที่อ่านได้" in answer


def test_fallback_verdict_is_taken_from_scoring_finding_only():
    findings = _scoring_findings("SUSPICIOUS")
    answer = build_final_answer_fallback(findings, "Investigate 1.2.3.4")

    assert extract_deterministic_verdict(findings) == "SUSPICIOUS"
    assert "SUSPICIOUS" in answer
    assert "CLEAN" not in answer


def test_agent_loop_sanitizes_before_persisting_final_answer():
    source = (Path(__file__).parents[1] / "src" / "agent" / "agent_loop.py").read_text(
        encoding="utf-8"
    )
    sanitize_at = source.index("sanitize_final_answer(raw_summary, state.findings, state.goal)")
    persist_at = source.index("state.add_finding({", sanitize_at)

    assert "contains_tool_call_template(raw_summary)" in source
    assert "logger.warning(" in source[sanitize_at:persist_at]
    assert "[:200]" in source[sanitize_at:persist_at]
    assert sanitize_at < persist_at
