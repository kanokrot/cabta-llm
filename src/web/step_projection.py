"""Safe, deterministic presentation for individual agent tool steps."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from src.agent.follow_up_suggestions import validate_ioc
from src.agent.local_tool_presentation import get_local_tool_presentation
from src.agent.mcp_tool_presentation import (
    ADDITIONAL_STATIC_MCP_PRESENTATION,
    MCP_TOOL_PRESENTATION,
    MCP_SERVER_GROUP_LABELS,
    get_mcp_tool_presentation,
)


MAX_RESULT_JSON = 65_536
MAX_SUMMARY_INTEGER = 1_000_000
_VERDICTS = {"CLEAN", "UNKNOWN", "SUSPICIOUS", "MALICIOUS"}
_INPUT_KEYS = ("ioc", "ip", "target", "indicator", "domain", "hash_value")


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= MAX_SUMMARY_INTEGER else None


def _duration(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _decode_result(value: Any) -> dict[str, Any] | None:
    """Decode at most one JSON string layer and one MCP result envelope."""
    if isinstance(value, str):
        if len(value) > MAX_RESULT_JSON:
            return None
        try:
            value = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None
    if not isinstance(value, Mapping):
        return None
    nested = value.get("result")
    if isinstance(nested, Mapping):
        value = nested
    elif isinstance(nested, str):
        if len(nested) > MAX_RESULT_JSON:
            return None
        try:
            value = json.loads(nested)
        except (TypeError, json.JSONDecodeError):
            return None
    return dict(value) if isinstance(value, Mapping) else None


def _tool_identity(
    tool_name: Any, tool_source: Any, tool_server: Any,
) -> tuple[str, str, str, str]:
    raw_name = tool_name if isinstance(tool_name, str) else ""
    source = tool_source if isinstance(tool_source, str) else ""
    server = tool_server if isinstance(tool_server, str) else ""
    if not server and "." in raw_name:
        server, raw_name = raw_name.split(".", 1)
        source = source or server
    elif server and raw_name.startswith(server + "."):
        raw_name = raw_name[len(server) + 1:]

    if source == "local" or (not server and source in {"", "local"}):
        presentation = get_local_tool_presentation(raw_name)
        display = presentation.display_name if presentation else _readable_name(raw_name)
        return raw_name, "local", "", display

    server = server or source
    presentation = get_mcp_tool_presentation(server, raw_name)
    return raw_name, "mcp", server, presentation.display_name


def _readable_name(value: str) -> str:
    readable = re.sub(r"[._-]+", " ", value).strip()
    return " ".join(part.capitalize() for part in readable.split()) or "Tool"


def _validated_input(params: Any) -> str | None:
    if isinstance(params, str):
        if len(params) > MAX_RESULT_JSON:
            return None
        try:
            params = json.loads(params)
        except (TypeError, json.JSONDecodeError):
            return None
    if not isinstance(params, Mapping):
        return None
    for key in _INPUT_KEYS:
        value = params.get(key)
        if isinstance(value, str) and len(value) <= 253:
            canonical = validate_ioc(value, allow_private=True)
            if canonical is not None and len(canonical) <= 253:
                return canonical
    return None


def _scoring_summary(scoring_context: Any) -> tuple[str | None, str]:
    from src.agent.agent_response_parsing import (
        _scoring_source_coverage,
        build_evidence_card,
    )

    if isinstance(scoring_context, Mapping):
        findings = [scoring_context]
    elif isinstance(scoring_context, list):
        findings = scoring_context
    else:
        return None, "unknown"
    evidence = build_evidence_card(findings, "")
    if not isinstance(evidence, Mapping):
        return None, "unknown"
    verdict = evidence.get("verdict")
    score = _integer(evidence.get("threat_score"))
    if not isinstance(verdict, str) or verdict.strip().upper() not in _VERDICTS:
        return None, "unknown"
    verdict = verdict.strip().upper()
    if score is None or score > 100:
        return None, "unknown"
    responding, total = _scoring_source_coverage(evidence)
    if not isinstance(total, int) or total <= 0 or responding < 0 or responding > total:
        return None, "unknown"
    status = "hit" if verdict in {"SUSPICIOUS", "MALICIOUS"} else "ok"
    return f"{verdict} · {score}/100 · {responding} of {total} sources responded", status


def _summary(tool_name: str, result: dict[str, Any] | None, scoring_context: Any) -> tuple[str | None, str]:
    if result is None:
        return None, "unknown"
    error = result.get("error")
    if error not in (None, "", False, 0):
        return None, "error"

    if tool_name == "investigate_ioc":
        return _scoring_summary(scoring_context)
    if tool_name == "blocklist_check":
        malicious = result.get("malicious")
        checked = _integer(result.get("lists_checked"))
        if type(malicious) is not bool or checked is None:
            return None, "unknown"
        if malicious:
            return f"Listed on one or more blocklists · {checked} checked", "hit"
        return f"Not listed · {checked} blocklists checked", "ok"
    if tool_name == "feodo_tracker_check":
        malicious = result.get("malicious")
        if type(malicious) is not bool:
            return None, "unknown"
        return ("Listed in Feodo Tracker", "hit") if malicious else ("Not listed in Feodo Tracker", "ok")
    if tool_name == "tor_exit_node_check":
        is_tor = result.get("is_tor_exit_node")
        if type(is_tor) is not bool:
            return None, "unknown"
        return ("Known Tor exit node", "hit") if is_tor else ("Not a Tor exit node", "ok")
    if tool_name == "yara_scan":
        if "matches" in result:
            matches = result.get("matches")
            if not isinstance(matches, list) or len(matches) > MAX_SUMMARY_INTEGER:
                return None, "unknown"
            count = len(matches)
        else:
            count = _integer(result.get("match_count"))
            if count is None:
                return None, "unknown"
        return (f"{count} YARA matches", "hit") if count else ("No YARA matches", "ok")
    if tool_name == "reverse_dns":
        hostname = result.get("hostname")
        if hostname is None or (isinstance(hostname, str) and not hostname.strip()):
            return "No PTR record", "ok"
        if isinstance(hostname, str):
            return "PTR record found", "ok"
        return None, "unknown"
    return None, "ok"


def project_agent_step(
    tool_name: Any,
    tool_source: Any = None,
    tool_server: Any = None,
    params: Any = None,
    result: Any = None,
    duration_ms: Any = None,
    scoring_context: Any = None,
) -> dict[str, Any]:
    """Project one agent tool call to fixed labels and validated scalar data."""
    raw_name, kind, server, display_name = _tool_identity(
        tool_name, tool_source, tool_server,
    )
    group_label = (
        "Local" if kind == "local"
        else MCP_SERVER_GROUP_LABELS.get(server, "MCP")
    )
    decoded = _decode_result(result)
    if raw_name == "investigate_ioc" and scoring_context is None and decoded is not None:
        scoring_context = {"tool": raw_name, "result": decoded}
    summary, status = _summary(raw_name, decoded, scoring_context)
    known_tool = (
        kind == "local" and get_local_tool_presentation(raw_name) is not None
    ) or (
        kind == "mcp"
        and (server, raw_name) in MCP_TOOL_PRESENTATION | ADDITIONAL_STATIC_MCP_PRESENTATION
    )
    if not known_tool and status == "ok":
        status = "unknown"
    duration = _duration(duration_ms)
    if decoded is None:
        status, summary = "unknown", None
    return {
        "display_name": display_name,
        "group_label": group_label,
        "status": status,
        "duration_ms": duration,
        "summary": summary,
        "input": (
            _validated_input(params)
            if known_tool else None
        ),
    }
