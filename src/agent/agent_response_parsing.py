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
