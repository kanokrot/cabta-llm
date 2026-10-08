from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.agent.agent_response_parsing import (
    build_evidence_card,
    extract_deterministic_verdict,
    select_scoring_finding,
)
from src.scoring.intelligent_scoring import (
    IntelligentScoring,
    SOURCE_SCORING_MULTIPLIERS,
)
from src.web.visibility import (
    _safe_evidence,
    serialize_agent_session,
    serialize_websocket_frame,
)
from src.web.websocket import _stored_agent_evidence


def _finding(tool="investigate_ioc"):
    sources = {
        "feodotracker": {"status": "\u2717", "found": False, "score": 0},
        "c2_trackers": {"status": "\u2717", "found": False, "score": 0},
        "spamhaus": {"status": "\u2717", "found": False, "score": 0},
        "tor_exit_nodes": {"status": "\u2717", "found": False, "score": 0},
        "sslblacklist": {
            "status": "\u26a0",
            "error": "feed unavailable",
            "score": 0,
            "api_key": "must-not-leak",
        },
        "threatfox": {"status": "\u2717", "found": False, "score": 0},
        "virustotal": {
            "status": "\u2717",
            "score": 0,
            "hostnames": ["private.example"],
            "ports": [443],
        },
        "censys": {"status": "\u2796", "ports": [443]},
        "talos": {"status": "\u26a0", "url": "https://example.test", "score": 0},
        "extra_na": {"status": "\u2717", "not_applicable": True},
    }
    return {
        "type": "tool_result",
        "tool": tool,
        "result": {
            "ioc": "8.8.8.8",
            "ioc_type": "ipv4",
            "threat_score": 0,
            "verdict": "CLEAN",
            "coverage": {
                "sources_flagged": 0,
                "sources_clean": 6,
                "sources_unavailable": 3,
                "total_sources_attempted": 9,
                "group_a": {"ignored": "not forwarded"},
            },
            "sources": sources,
            "threat_intel_results": {"leak": "must-not-read"},
            "threat_intelligence": {"leak": "must-not-read"},
            "llm_analysis": {"leak": "must-not-read"},
            "detection_rules": {"leak": "must-not-read"},
        },
    }


def test_evidence_card_uses_scoring_result_sources_and_engine_values():
    findings = [_finding()]
    card = build_evidence_card(findings, "analyze 8.8.8.8")

    assert card is not None
    assert [row["name"] for row in card["scoring_sources"]] == [
        "feodotracker",
        "c2_trackers",
        "spamhaus",
        "sslblacklist",
        "tor_exit_nodes",
        "threatfox",
    ]
    assert card["scoring_sources"][3]["state"] == "unavailable"
    assert {
        row["name"]: row["weight"] for row in card["scoring_sources"]
    } == {
        name: round(weight, 2)
        for name, weight in SOURCE_SCORING_MULTIPLIERS.items()
    }
    assert card["coverage"] == {
        "flagged": 0,
        "clean": 6,
        "unavailable": 3,
        "attempted": 9,
    }
    assert card["verdict"] == extract_deterministic_verdict(findings)
    assert card["threat_score"] == findings[0]["result"]["threat_score"]
    assert card["lang"] == "en"
    assert card["not_applicable_count"] == 2


def test_tier_map_tracks_the_scoring_engine_and_card_is_bounded():
    card = build_evidence_card([_finding()], "analyze 8.8.8.8")
    assert card is not None
    assert {row["name"] for row in card["scoring_sources"]} == set(
        SOURCE_SCORING_MULTIPLIERS
    )
    assert len(json.dumps(card, ensure_ascii=False).encode("utf-8")) <= 4096
    serialized = json.dumps(card, ensure_ascii=False)
    for excluded in (
        "llm_analysis",
        "detection_rules",
        "hostnames",
        "ports",
        "error",
        "url",
        "api_key",
        "must-not-leak",
        "private.example",
    ):
        assert excluded not in serialized
    assert card["extra_sources"] == [
        {"name": "virustotal", "state": "clean"},
        {"name": "talos", "state": "unavailable"},
    ]


@pytest.mark.parametrize(
    "findings",
    [
        [],
        [_finding("analyze_malware")],
        [_finding("threat_intel_tools.recent_malware_samples")],
    ],
)
def test_non_ioc_scoring_findings_do_not_create_cards(findings):
    assert build_evidence_card(findings, "goal") is None


def test_latest_scoring_finding_controls_verdict_and_card():
    findings = [
        _finding(),
        {
            "tool": "analyze_malware",
            "result": {"verdict": "SUSPICIOUS"},
        },
    ]
    assert select_scoring_finding(findings) is findings[1]
    assert extract_deterministic_verdict(findings) == "SUSPICIOUS"
    assert build_evidence_card(findings, "goal") is None


def test_evidence_card_localizes_from_goal():
    card = build_evidence_card([_finding()], "\u0e27\u0e34\u0e40\u0e04\u0e23\u0e32\u0e30\u0e2b\u0e4c 8.8.8.8")
    assert card is not None
    assert card["lang"] == "th"


def test_evidence_card_failure_does_not_raise(monkeypatch):
    def fail_score(_source_data):
        raise RuntimeError("scoring helper failed")

    monkeypatch.setattr(IntelligentScoring, "_get_source_score", fail_score)
    assert build_evidence_card([_finding()], "analyze 8.8.8.8") is None


def test_safe_evidence_drops_unknown_keys_and_rejects_invalid_types():
    card = build_evidence_card([_finding()], "goal")
    assert card is not None
    with_unknown = dict(card, raw_result={"api_key": "secret"})
    safe = _safe_evidence(with_unknown)
    assert safe is not None
    assert "raw_result" not in safe

    bad_state = json.loads(json.dumps(card))
    bad_state["scoring_sources"][0]["state"] = "unknown"
    assert _safe_evidence(bad_state) is None

    bad_type = dict(card, threat_score="0")
    assert _safe_evidence(bad_type) is None


def test_safe_evidence_truncates_names_and_drops_unknown_nested_keys():
    card = build_evidence_card([_finding()], "goal")
    assert card is not None
    card["scoring_sources"][0]["name"] = "x" * 200
    card["scoring_sources"][0]["unexpected"] = "discard"
    card["extra_sources"][0]["name"] = "y" * 200
    safe = _safe_evidence(card)

    assert safe is not None
    assert safe["scoring_sources"][0]["name"] == "x" * 64
    assert safe["extra_sources"][0]["name"] == "y" * 64
    assert "unexpected" not in safe["scoring_sources"][0]


def test_evidence_flows_through_agent_visibility_and_final_answer_history():
    card = build_evidence_card([_finding()], "goal")
    assert card is not None
    completed = serialize_websocket_frame(
        {"type": "completed", "summary": "done", "verdict": "CLEAN",
         "verdict_source": {"tool": "investigate_ioc", "step": 0}, "evidence": card},
        role="admin",
        flow="websocket_agent",
    )
    without_evidence = serialize_websocket_frame(
        {"type": "completed", "summary": "done", "verdict": "CLEAN",
         "verdict_source": {"tool": "investigate_ioc", "step": 0}},
        role="admin",
        flow="websocket_agent",
    )
    playbook = serialize_websocket_frame(
        {"type": "completed", "summary": "done", "evidence": card},
        role="admin",
        flow="websocket_playbook",
    )
    session = serialize_agent_session(
        {"id": "session-1", "goal": "goal"},
        steps=[{
            "step_number": 9,
            "step_type": "final_answer",
            "content": json.dumps({
                "answer": "done",
                "verdict": "CLEAN",
                "verdict_source": {"tool": "investigate_ioc", "step": 0},
                "evidence": card,
            }),
        }],
        role="admin",
    )

    assert completed["evidence"] == card
    assert "evidence" not in without_evidence
    assert playbook == {"type": "completed", "summary": "done"}
    assert session["history"][-1]["evidence"] == card


def test_history_keeps_evidence_when_final_answer_content_exceeds_4000_chars():
    card = build_evidence_card([_finding()], "goal")
    assert card is not None
    session = serialize_agent_session(
        {"id": "session-long", "goal": "goal"},
        steps=[{
            "step_number": 9,
            "step_type": "final_answer",
            "content": json.dumps({
                "answer": "long answer " * 500,
                "verdict": "CLEAN",
                "verdict_source": {"tool": "investigate_ioc", "step": 0},
                "evidence": card,
            }),
        }],
        role="admin",
    )

    assert session["history"][-1]["evidence"] == card


def test_replayed_agent_evidence_comes_from_final_answer_step():
    card = build_evidence_card([_finding()], "goal")
    assert card is not None
    steps = [
        {"step_type": "tool_call", "content": json.dumps({"evidence": {"bad": True}})},
        {
            "step_type": "final_answer",
            "content": json.dumps({
                "action": "final_answer", "verdict": "CLEAN",
                "verdict_source": {"tool": "investigate_ioc", "step": 0},
                "evidence": card,
            }),
        },
    ]
    assert _stored_agent_evidence(steps) == card
    assert _stored_agent_evidence(steps[:1]) is None


def test_evidence_renderer_uses_text_nodes_and_is_called_in_all_paths():
    template = Path("templates/agent_chat.html").read_text(encoding="utf-8")
    renderer = template.split("function renderEvidenceCard(evidence, verdictSource)", 1)[1].split(
        "function addBubble", 1
    )[0]

    assert "innerHTML" not in renderer
    assert "textContent" in renderer
    assert "do not cover this IOC type" in renderer
    assert "!sourceLabel || verdictSource.tool !== 'investigate_ioc'" in renderer
    unavailable_filter = renderer.split("var unavailableCount", 1)[1].split(
        "if (unavailableCount", 1
    )[0]
    assert "source.state === 'unavailable'" in unavailable_filter
    assert "source.state === 'missing'" not in unavailable_filter
    assert template.count("renderEvidenceCard(") >= 5
    assert "renderEvidenceCard(m.evidence, m.verdict_source)" in template
    assert "renderEvidenceCard(msg.evidence, msg.verdict_source)" in template
