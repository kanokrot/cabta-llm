"""
Agent response parsing helpers - pure functions for turning raw LLM output
into the AgentLoop's standard decision dict, with no dependency on
AgentLoop instance state.
"""

import json
import logging
import re
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

_TOOL_CALL_BLOCK_RE = re.compile(
    r"<\|tool_call>[\s\S]*?(?:<tool_call\|>|$)", re.IGNORECASE,
)
_TOOL_CALL_MARKER_RE = re.compile(
    r"<\|tool_call>|<tool_call\|>|<\|[^<>\r\n]{1,100}\|>", re.IGNORECASE,
)


def contains_tool_call_template(text: Any) -> bool:
    """Detect leaked tool-call markup and model special tokens in answer text."""
    return isinstance(text, str) and bool(_TOOL_CALL_MARKER_RE.search(text))


def _strip_tool_call_template(text: str) -> str:
    cleaned = _TOOL_CALL_BLOCK_RE.sub(" ", text)
    cleaned = _TOOL_CALL_MARKER_RE.sub(" ", cleaned)
    cleaned = re.sub(
        r"\s*\[(?:MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN)\]\s*",
        " ",
        cleaned,
        flags=re.IGNORECASE,
    )
    return re.sub(r"\s+", " ", cleaned).strip()


def _meaningful_character_count(text: str) -> int:
    return sum(1 for char in text if char.isalnum())


def _answer_language(goal: Any) -> str:
    return "th" if isinstance(goal, str) and any("\u0e00" <= char <= "\u0e7f" for char in goal) else "en"


def _scoring_source_coverage(evidence: dict) -> tuple[int, int]:
    """Count replies from the exact scoring-source rows shown in evidence."""
    rows = evidence.get("scoring_sources")
    if not isinstance(rows, list):
        return 0, 0
    responding = sum(
        1 for row in rows
        if isinstance(row, dict) and row.get("state") in {"flagged", "clean"}
    )
    return responding, len(rows)


def build_final_answer_fallback(findings: list, goal: str) -> str:
    """Create a concise answer from scoring evidence, or a neutral no-answer notice."""
    language = _answer_language(goal)
    evidence = build_evidence_card(findings, goal)
    if evidence is not None:
        responding, total = _scoring_source_coverage(evidence)
        verdict = evidence["verdict"]
        score = evidence["threat_score"]
        ioc = evidence["ioc"]
        if language == "th":
            return (
                f"ผล scoring: {verdict} · {score}/100 · {responding} จาก {total} แหล่งตอบกลับ "
                f"สำหรับ {ioc} โมเดลไม่ได้ส่งข้อความสรุปที่อ่านได้ โปรดดูตารางหลักฐาน"
            )
        return (
            f"Scoring result: {verdict} · {score}/100 · {responding} of {total} sources responded "
            f"for {ioc}. No readable model summary was provided; see the evidence table."
        )

    finding = select_scoring_finding(findings)
    if finding is not None:
        result = finding.get("result")
        if isinstance(result, dict):
            verdict = result.get("verdict")
            score = result.get("threat_score", result.get("score"))
            ioc = result.get("ioc")
            if isinstance(verdict, str) and verdict.strip():
                score_text = (
                    f" · {score}/100"
                    if isinstance(score, (int, float)) and not isinstance(score, bool)
                    else ""
                )
                ioc_text = f" · {ioc[:256]}" if isinstance(ioc, str) and ioc else ""
                if language == "th":
                    return f"ผล scoring: {verdict.strip().upper()}{score_text}{ioc_text} โมเดลไม่ได้ส่งข้อความสรุปที่อ่านได้"
                return f"Scoring result: {verdict.strip().upper()}{score_text}{ioc_text}. No readable model summary was provided."

    return (
        "โมเดลไม่ได้ส่งคำตอบที่อ่านได้"
        if language == "th"
        else "The model did not provide a readable answer."
    )


def sanitize_final_answer(answer: Any, findings: list, goal: str) -> str:
    """Remove leaked tool-call template text without interpreting it as a call."""
    raw = answer if isinstance(answer, str) else str(answer or "")
    if not contains_tool_call_template(raw):
        return raw
    cleaned = _strip_tool_call_template(raw)
    if _meaningful_character_count(cleaned) < 20:
        return build_final_answer_fallback(findings, goal)
    return cleaned


def extract_verdict(text: str) -> str:
    """Extract verdict keyword from text.

    [FIX] Prefer an explicit "Verdict: X" label over a naive substring
    scan.  A naive scan for 'MALICIOUS' anywhere in the text incorrectly
    matches phrases like "does not appear malicious" or "none ... appear
    to be malicious", even when the analysis clearly concludes CLEAN.
    """
    # 1) Look for an explicit "Verdict: X" (or "**Verdict:** X") label first
    m = re.search(r'verdict[:\s\*]+\s*(MALICIOUS|SUSPICIOUS|CLEAN)', text, re.IGNORECASE)
    if m:
        return m.group(1).upper()

    # 2) Fallback: naive keyword scan (kept for safety, but now secondary)
    text_upper = text.upper()
    if 'MALICIOUS' in text_upper:
        return 'MALICIOUS'
    if 'SUSPICIOUS' in text_upper:
        return 'SUSPICIOUS'
    if 'CLEAN' in text_upper:
        return 'CLEAN'
    return 'UNKNOWN'


def normalise_decision(
    parsed: Dict,
    state,
    guess_first_tool: Callable[[str], str],
    guess_tool_params: Callable[[str], dict],
) -> Dict:
    """Normalise various JSON formats the LLM might return into our
    standard decision dict ``{action, tool, params, reasoning}``.

    Handles:
    - Ollama text tool-call: ``{"name": "...", "parameters": {...}}``
    - Ollama text tool-call: ``{"name": "...", "arguments": {...}}``
    - Decision with nested params: ``{"action": "use_tool", "tool": "...",
      "params": {"action": "...", ...}}``
    - Standard format (pass through)
    - ``final_answer`` with no findings → auto-dispatch to tool
    """
    # --- Ollama text tool-call format ---
    # LLM writes JSON like {"name": "investigate_ioc", "parameters": {"ioc": "..."}}
    if 'name' in parsed and 'action' not in parsed:
        tool_name = parsed['name']
        params = parsed.get('parameters', parsed.get('arguments', {}))
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = {}
        logger.info(
            f"[AGENT] Normalised Ollama text tool-call: "
            f"tool={tool_name}, params={params}"
        )
        return {
            "action": "use_tool",
            "tool": tool_name,
            "params": params if isinstance(params, dict) else {},
            "reasoning": parsed.get("reasoning", "LLM text tool-call"),
        }

    # --- final_answer with no findings → force tool use ---
    if parsed.get('action') == 'final_answer' and not state.findings:
        logger.warning(
            "[AGENT] LLM tried final_answer with no findings. "
            "Auto-dispatching tool."
        )
        return {
            "action": "use_tool",
            "tool": guess_first_tool(state.goal),
            "params": guess_tool_params(state.goal),
            "reasoning": "Auto-dispatched: LLM skipped tool use",
        }

    # --- Bare params dict (no action/name/tool key) → auto-dispatch ---
    # LLM returned just the params like {"ioc": "..."} without wrapping
    if 'action' not in parsed and 'name' not in parsed and 'tool' not in parsed:
        logger.warning(
            "[AGENT] LLM returned bare params without action/name. "
            "Auto-dispatching tool. parsed=%s", parsed,
        )
        guessed_tool = guess_first_tool(state.goal)
        guessed_params = guess_tool_params(state.goal)
        # Merge LLM's parsed output with guessed params (LLM's take priority)
        final_params = {**guessed_params, **parsed}
        return {
            "action": "use_tool",
            "tool": guessed_tool,
            "params": final_params,
            "reasoning": "Auto-dispatched: LLM returned bare params",
        }

    # --- Standard format: pass through ---
    return parsed


def parse_tool_call_response(raw: Dict) -> Optional[Dict]:
    """Convert native tool_call response into our standard decision dict.

    Handles the common case where the LLM merges the system prompt's
    JSON format into the tool_call arguments, producing::

        arguments: {
            "params": {"ioc": "8.8.8.8"},
            "action": "use_tool",
            "tool": "investigate_ioc",
            "reasoning": "..."
        }

    instead of the expected ``{"ioc": "8.8.8.8"}``.
    """
    calls = raw.get("tool_calls", [])
    if not calls:
        return None
    first = calls[0]
    func = first.get("function", first)
    name = func.get("name", "")
    args = func.get("arguments", {})
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    if not isinstance(args, dict):
        args = {}

    # ---- Unwrap nested params ----
    # If the LLM stuffed the full decision JSON into tool_call arguments,
    # the REAL tool parameters live under args["params"].
    if "params" in args and isinstance(args["params"], dict):
        nested = args["params"]
        # Verify this looks like the system-prompt JSON leak
        # (has 'action' or 'tool' or 'reasoning' alongside 'params')
        has_decision_keys = any(
            k in args for k in ("action", "tool", "reasoning")
        )
        if has_decision_keys or len(nested) > 0:
            reasoning = args.get("reasoning", "Selected by LLM tool_call")
            # Use the tool name from the native call (more reliable)
            # but fall back to args["tool"] if the native name is empty
            if not name and args.get("tool"):
                name = args["tool"]
            args = nested
            logger.info(
                f"[AGENT] Unwrapped nested params for {name}: {args}"
            )

    logger.info(
        f"[AGENT] Parsed tool_call: tool={name}, args={args}, "
        f"raw_first={json.dumps(first, default=str)[:300]}"
    )
    return {
        "action": "use_tool",
        "tool": name,
        "params": args,
        "reasoning": args.pop("reasoning", "Selected by LLM tool_call")
                     if "reasoning" in args else "Selected by LLM tool_call",
    }


def extract_json(text: str) -> Optional[Dict]:
    """Best-effort extraction of a JSON object from LLM text output."""
    if not text:
        return None

    # 1. Try parsing entire text as JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Try extracting from code blocks
    m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Find first { ... } block
    start = text.find('{')
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break

    return None


def truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[:max_len] + "..."


def select_scoring_finding(findings: list) -> Optional[dict]:
    """Return the latest finding with an authoritative scoring-tool verdict."""
    scoring_tools = {"investigate_ioc", "analyze_malware", "analyze_email"}
    if not isinstance(findings, (list, tuple)):
        return None
    for finding in reversed(findings):
        if not isinstance(finding, dict) or finding.get("tool") not in scoring_tools:
            continue
        result = finding.get("result")
        if isinstance(result, dict):
            verdict = result.get("verdict")
            if isinstance(verdict, str) and verdict.strip():
                return finding
    return None


def extract_deterministic_verdict(findings: list) -> Optional[str]:
    """สแกน findings ย้อนหลังหา verdict ที่เป็น deterministic จาก tool result (ถ้ามี)
    เพื่อใช้แทน verdict ที่ LLM เดาเองจาก text"""
    finding = select_scoring_finding(findings)
    if finding is None:
        return None
    result = finding.get("result")
    verdict = result.get("verdict") if isinstance(result, dict) else None
    return verdict.strip().upper() if isinstance(verdict, str) and verdict.strip() else None


def extract_deterministic_verdict_source(findings: list) -> Optional[dict]:
    """Return the scoring tool and zero-based agent step backing the verdict."""
    finding = select_scoring_finding(findings)
    if finding is None:
        return None
    step = finding.get("step")
    if isinstance(step, bool) or not isinstance(step, int) or step < 0:
        return None
    return {"tool": finding["tool"], "step": step}


def build_evidence_card(findings: list, goal: str) -> Optional[dict]:
    try:
        return _build_evidence_card(findings, goal)
    except Exception as exc:
        logging.getLogger(__name__).warning("Could not build evidence card: %s", exc)
        return None


def _build_evidence_card(findings: list, goal: str) -> Optional[dict]:
    """Build a compact, allowlisted card from the selected IOC scoring result."""
    finding = select_scoring_finding(findings)
    if finding is None or finding.get("tool") != "investigate_ioc":
        return None
    result = finding.get("result")
    if not isinstance(result, dict):
        return None

    from ..scoring.intelligent_scoring import (
        IntelligentScoring,
        SOURCE_SCORING_MULTIPLIERS,
    )

    source_tiers = {
        "feodotracker": "high",
        "c2_trackers": "medium",
        "spamhaus": "medium",
        "tor_exit_nodes": "medium",
        "sslblacklist": "medium",
        "threatfox": "low",
    }
    if set(source_tiers) != set(SOURCE_SCORING_MULTIPLIERS):
        return None

    ioc = result.get("ioc")
    ioc_type = result.get("ioc_type")
    threat_score = result.get("threat_score")
    verdict = result.get("verdict")
    if (
        not isinstance(ioc, str)
        or not isinstance(ioc_type, str)
        or isinstance(threat_score, bool)
        or not isinstance(threat_score, int)
        or not isinstance(verdict, str)
        or not verdict.strip()
    ):
        return None

    sources = result.get("sources")
    if not isinstance(sources, dict):
        sources = {}

    def is_not_applicable(source_data: dict) -> bool:
        status = str(source_data.get("status", "")).strip()
        reason = str(
            source_data.get("error") or source_data.get("message") or ""
        ).strip().lower()
        return (
            source_data.get("not_applicable") is True
            or status == "\u2796"
            or reason == "not applicable"
        )

    def source_state(source_data: dict) -> str:
        if IntelligentScoring._is_source_error(source_data):
            return "unavailable"
        score = IntelligentScoring._get_source_score(source_data)
        if score is None:
            return "unavailable"
        return "flagged" if score > 0 else "clean"

    tier_order = {"high": 0, "medium": 1, "low": 2}
    scoring_rows = []
    for name in source_tiers:
        source_data = sources.get(name)
        if not isinstance(source_data, dict):
            state = "missing"
            score = 0
        elif is_not_applicable(source_data):
            state = "missing"
            score = IntelligentScoring._get_source_score(source_data)
        else:
            state = source_state(source_data)
            score = IntelligentScoring._get_source_score(source_data)
        scoring_rows.append({
            "name": name,
            "tier": source_tiers[name],
            "weight": round(float(SOURCE_SCORING_MULTIPLIERS[name]), 2),
            "state": state,
            "score": int(score or 0),
        })
    scoring_rows.sort(key=lambda row: (tier_order[row["tier"]], row["name"]))

    coverage_result = result.get("coverage")
    if not isinstance(coverage_result, dict):
        coverage_result = {}

    def coverage_count(key: str) -> int:
        value = coverage_result.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    card = {
        "lang": _answer_language(goal),
        "ioc": ioc[:256],
        "ioc_type": ioc_type[:32],
        "threat_score": threat_score,
        "verdict": verdict.strip()[:32],
        "scoring_sources": scoring_rows,
        "extra_sources": [],
        "not_applicable_count": 0,
        "coverage": {
            "flagged": coverage_count("sources_flagged"),
            "clean": coverage_count("sources_clean"),
            "unavailable": coverage_count("sources_unavailable"),
            "attempted": coverage_count("total_sources_attempted"),
        },
    }

    extra_rows = []
    for name, source_data in sources.items():
        if not isinstance(name, str) or not isinstance(source_data, dict):
            continue
        if name.lower() in source_tiers:
            if is_not_applicable(source_data):
                card["not_applicable_count"] += 1
            continue
        if is_not_applicable(source_data):
            card["not_applicable_count"] += 1
            continue
        extra_rows.append({"name": name[:64], "state": source_state(source_data)})
    card["extra_sources"] = extra_rows[:30]

    def card_size(value: dict) -> int:
        return len(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )

    while card["extra_sources"] and card_size(card) > 4096:
        card["extra_sources"].pop()
    if card_size(card) > 4096:
        return None
    return card


def sanitize_unscored_answer(text: str, goal: str) -> str:
    """Remove an LLM-authored verdict label and append a language-matched notice."""
    answer = text if isinstance(text, str) else str(text or "")
    answer = re.sub(
        r"\bVerdict\s*:\s*(?:MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN)\b",
        "",
        answer,
        flags=re.IGNORECASE,
    )
    answer = re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", answer).strip()
    goal_text = goal if isinstance(goal, str) else str(goal or "")
    if any("\u0e00" <= char <= "\u0e7f" for char in goal_text):
        notice = "\u0e44\u0e21\u0e48\u0e21\u0e35\u0e1c\u0e25\u0e1b\u0e23\u0e30\u0e40\u0e21\u0e34\u0e19\u0e08\u0e32\u0e01 scoring engine \u2014 \u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e19\u0e35\u0e49\u0e40\u0e1b\u0e47\u0e19\u0e2a\u0e23\u0e38\u0e1b\u0e02\u0e2d\u0e07 LLM \u0e44\u0e21\u0e48\u0e43\u0e0a\u0e48 verdict"
    else:
        notice = "No scoring-engine result \u2014 this is an LLM summary, not a verdict."
    if answer.endswith(notice):
        return answer
    return f"{answer}\n\n{notice}" if answer else notice
