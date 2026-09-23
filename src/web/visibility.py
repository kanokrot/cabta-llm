"""Centralized, fail-closed response visibility policy."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Mapping, Optional


SOC = "SOC Analyst Tier 1-2"
INCIDENT_RESPONDER = "Incident Responder"
THREAT_HUNTER = "Threat Hunter"
TEAM_LEAD = "Team Lead"
ADMIN = "admin"

VALID_ROLES = frozenset({SOC, INCIDENT_RESPONDER, THREAT_HUNTER, TEAM_LEAD, ADMIN})
VALID_FLOWS = frozenset({
    "analysis", "dashboard", "report", "chat", "agent", "playbook", "case",
    "websocket_analysis", "websocket_agent", "gmail", "gmail_admin",
})


class VisibilityError(ValueError):
    """Raised when a role, flow, or payload cannot be safely serialized."""


def _policy_roles(flow: str) -> frozenset[str]:
    if flow in {"analysis", "dashboard", "report", "case", "websocket_analysis"}:
        return frozenset(VALID_ROLES)
    if flow == "chat":
        return frozenset({INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN})
    if flow in {"agent", "websocket_agent"}:
        return frozenset({THREAT_HUNTER, ADMIN})
    if flow == "gmail":
        return frozenset(VALID_ROLES)
    if flow == "gmail_admin":
        return frozenset({ADMIN})
    if flow == "playbook":
        return frozenset({INCIDENT_RESPONDER, ADMIN})
    raise VisibilityError(f"Unknown visibility flow: {flow!r}")


def authorize_flow(role: Any, flow: str) -> None:
    """Fail closed for unknown roles/flows and unauthorized flow access."""
    if role not in VALID_ROLES:
        raise VisibilityError("Unknown visibility role")
    if flow not in VALID_FLOWS:
        raise VisibilityError("Unknown visibility flow")
    if role not in _policy_roles(flow):
        raise VisibilityError("Role is not allowed to access this flow")


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _text(value: Any, limit: int = 2000) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:limit]
    return None


def _scalar_list(value: Any, limit: int = 100) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        return []
    result = []
    for item in value[:limit]:
        if isinstance(item, (str, int, float, bool)):
            result.append(str(item)[:500] if isinstance(item, str) else item)
    return result


def serialize_gmail_status(status: Mapping[str, Any], role: str) -> dict[str, Any]:
    """Serialize only non-secret, owner-scoped Gmail connection status."""
    authorize_flow(role, "gmail")
    scopes = status.get("granted_scopes")
    return {
        "linked": bool(status.get("linked", False)),
        "google_email": _text(status.get("google_email"), 320),
        "granted_scopes": sorted(
            scope for scope in scopes if isinstance(scope, str) and scope in {
                "https://www.googleapis.com/auth/gmail.send", "openid", "email", "profile"
            }
        ) if isinstance(scopes, list) else [],
        "linked_at": _text(status.get("linked_at"), 64),
        "last_refresh_at": _text(status.get("last_refresh_at"), 64),
        "revoked": bool(status.get("revoked", False)),
    }


def serialize_gmail_summary(summary: Mapping[str, Any], role: str) -> dict[str, Any]:
    authorize_flow(role, "gmail_admin")
    by_role = summary.get("by_role")
    safe_roles = {}
    if isinstance(by_role, Mapping):
        for key in (SOC, INCIDENT_RESPONDER, THREAT_HUNTER, TEAM_LEAD, ADMIN):
            value = by_role.get(key, 0)
            if isinstance(value, int) and value >= 0:
                safe_roles[key] = value
    return {"linked_users": int(summary.get("linked_users", 0)), "by_role": safe_roles}


def _safe_mitre(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output = []
    for item in value[:100]:
        if not isinstance(item, dict):
            continue
        row = {}
        for key, source_key in (
            ("technique_id", item.get("technique_id", item.get("id"))),
            ("tactic", item.get("tactic")),
            ("technique", item.get("technique", item.get("name", item.get("technique_name")))),
            ("description", item.get("description")),
        ):
            safe = _text(source_key, 500)
            if safe is not None:
                row[key] = safe
        if row:
            output.append(row)
    return output


def _safe_sources(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, dict[str, Any]] = {}
    for source_name, source_value in list(value.items())[:100]:
        if not isinstance(source_name, str) or not isinstance(source_value, dict):
            continue
        row = {}
        for key in ("status", "score", "confidence", "detections", "total_engines"):
            if key in source_value and isinstance(source_value[key], (str, int, float, bool)):
                row[key] = source_value[key]
        if row:
            output[source_name[:100]] = row
    return output


def _safe_findings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    allowed = (
        "type", "tool", "verdict", "score", "confidence", "summary", "status",
        "source", "ioc", "id", "technique_id", "technique", "technique_name",
        "subtechnique", "capability", "tactic",
    )
    output = []
    for item in value[:100]:
        if not isinstance(item, dict):
            continue
        row = {}
        for key in allowed:
            value_item = item.get(key)
            if isinstance(value_item, (str, int, float, bool)):
                row[key] = str(value_item)[:1000] if isinstance(value_item, str) else value_item
        if row:
            output.append(row)
    return output


def _safe_result(
    result: Mapping[str, Any],
    *,
    detailed: bool,
    include_detection_rules: bool = False,
) -> dict[str, Any]:
    """Build a report-safe result from known presentation fields only."""
    output: dict[str, Any] = {}
    scalar_fields = (
        "ioc", "ioc_type", "verdict", "threat_score", "composite_score",
        "base_phishing_score", "sources_checked", "sources_flagged", "summary",
        "executive_summary", "confidence",
    )
    for key in scalar_fields:
        if key in result and isinstance(result[key], (str, int, float, bool)):
            output[key] = result[key]
    if isinstance(result.get("sources"), dict):
        output["sources"] = _safe_sources(result["sources"])
    if isinstance(result.get("recommendations"), list):
        output["recommendations"] = _scalar_list(result["recommendations"])
    for key in ("mitre_mapping", "mitre_techniques"):
        if isinstance(result.get(key), list):
            output[key] = _safe_mitre(result[key])
    if isinstance(result.get("findings"), list):
        output["findings"] = _safe_findings(result["findings"])

    if detailed:
        for key in ("hashes", "file_info", "scoring"):
            value = result.get(key)
            if isinstance(value, dict):
                output[key] = {
                    str(k): v for k, v in value.items()
                    if isinstance(k, str)
                    and isinstance(v, (str, int, float, bool))
                    and k.lower() not in {
                        "path", "file_path", "temp_path", "token", "password",
                        "secret", "credential", "credentials", "api_key",
                        "provider_payload", "raw_source",
                    }
                }
        capabilities = result.get("capabilities")
        if isinstance(capabilities, list):
            output["capabilities"] = _safe_findings(capabilities)
        elif isinstance(capabilities, dict):
            output["capabilities"] = {
                key: (
                    _safe_findings(value)
                    if key == "attack_techniques" and isinstance(value, list)
                    else _scalar_list(value) if isinstance(value, list) else value
                )
                for key, value in capabilities.items()
                if key in {"attack_techniques", "threat_score", "success"}
                and isinstance(value, (list, str, int, float, bool))
            }
    if detailed or include_detection_rules:
        rules = result.get("detection_rules")
        if isinstance(rules, dict):
            output["detection_rules"] = {
                str(key): _text(value, 20000)
                for key, value in rules.items()
                if isinstance(key, str) and _text(value, 20000) is not None
            }
    return output


def serialize_analysis_job(job: Dict[str, Any], role: str = SOC, flow: str = "analysis") -> Dict[str, Any]:
    """Serialize an analysis job using the role/flow allowlist."""
    authorize_flow(role, flow)
    params = _as_dict(job.get("params"))
    result = _as_dict(job.get("result"))
    output = {
        "id": job.get("id"),
        "analysis_type": job.get("analysis_type"),
        "status": job.get("status"),
        "progress": job.get("progress", 0),
        "current_step": _text(job.get("current_step", ""), 200),
        "verdict": job.get("verdict") or result.get("verdict") or "UNKNOWN",
        "score": job.get("score"),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "ioc": params.get("value"),
        "ioc_type": params.get("ioc_type"),
        "filename": params.get("filename"),
        "sha256": params.get("sha256"),
        "size": params.get("size"),
        "summary": _text(result.get("summary"), 4000),
        "confidence": result.get("confidence"),
    }
    return {key: value for key, value in output.items() if value is not None}


def serialize_dashboard_job(job: Dict[str, Any], role: str = SOC) -> Dict[str, Any]:
    authorize_flow(role, "dashboard")
    item = serialize_analysis_job(job, role=role, flow="dashboard")
    return {
        "id": item.get("id"), "ioc": item.get("ioc"), "filename": item.get("filename"),
        "ioc_type": item.get("ioc_type"), "type": item.get("analysis_type"),
        "status": item.get("status"), "verdict": item.get("verdict", "UNKNOWN"),
        "threat_score": item.get("score"), "created_at": item.get("created_at"),
        "completed_at": item.get("completed_at"),
    }


def serialize_report_job(job: Dict[str, Any], role: str = SOC) -> Dict[str, Any]:
    authorize_flow(role, "report")
    detailed = role in {INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN}
    base = serialize_analysis_job(job, role=role, flow="report")
    base["result"] = _safe_result(
        _as_dict(job.get("result")),
        detailed=detailed,
        include_detection_rules=True,
    )
    return base


def serialize_report_payload(job: Dict[str, Any], role: str = SOC) -> dict[str, Any]:
    return serialize_report_job(job, role=role)["result"]


def serialize_result_payload(result: Any, role: str) -> dict[str, Any]:
    """Serialize an arbitrary tool/report result for an agent-facing boundary."""
    authorize_flow(role, "agent")
    return _safe_result(_as_dict(result), detailed=role == ADMIN)


def serialize_playbook_result(result: Any, role: str) -> dict[str, Any]:
    authorize_flow(role, "playbook")
    result_dict = _as_dict(result)
    if "sources" in result_dict and not isinstance(result_dict["sources"], dict):
        raise VisibilityError("Invalid playbook report sources")
    return _safe_result(result_dict, detailed=role == ADMIN)


def serialize_report_mitre(job: Dict[str, Any], role: str = SOC) -> dict[str, Any]:
    authorize_flow(role, "report")
    result = _as_dict(job.get("result"))
    techniques = result.get("mitre_mapping") or result.get("mitre_techniques") or []
    safe = _safe_mitre(techniques)
    return {
        "name": f"BTA Analysis {job.get('id', '')}",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Auto-generated from analysis {job.get('id', '')}",
        "techniques": [
            {"techniqueID": item.get("technique_id", ""), "tactic": str(item.get("tactic", "")).lower().replace(" ", "-"),
             "color": "#e60d0d", "comment": item.get("technique", ""), "enabled": True}
            for item in safe
        ],
    }


def serialize_response(payload: Dict[str, Any], *, role: str, flow: str) -> dict[str, Any]:
    if flow == "analysis":
        return serialize_analysis_job(payload, role=role, flow=flow)
    if flow == "dashboard":
        return serialize_dashboard_job(payload, role=role)
    if flow == "report":
        return serialize_report_payload(payload, role=role)
    raise VisibilityError(f"No serializer for flow: {flow!r}")


def serialize_status(job: Dict[str, Any], role: str = SOC) -> dict[str, Any]:
    authorize_flow(role, "analysis")
    return {
        "analysis_id": job.get("id"), "status": job.get("status"),
        "progress": job.get("progress", 0),
        "current_step": _text(job.get("current_step", ""), 200),
        "verdict": job.get("verdict"), "score": job.get("score"),
    }


def _safe_session(session: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: session.get(key)
        for key in ("id", "status", "goal", "summary", "created_at", "updated_at", "playbook_id")
        if session.get(key) is not None
    }


def serialize_agent_step(step: Mapping[str, Any], role: str = THREAT_HUNTER) -> dict[str, Any]:
    authorize_flow(role, "agent")
    output = {}
    for key in ("id", "step_number", "step_type", "tool_name", "status", "duration_ms", "timestamp"):
        if key in step and isinstance(step[key], (str, int, float, bool)):
            output[key] = step[key]
    if "content" in step:
        output["summary"] = _text(step.get("content"), 2000)
    return {key: value for key, value in output.items() if value is not None}


def serialize_agent_session(session: Mapping[str, Any], steps: Optional[Iterable[Mapping[str, Any]]] = None,
                            live_state: Optional[Mapping[str, Any]] = None, role: str = THREAT_HUNTER) -> dict[str, Any]:
    authorize_flow(role, "agent")
    output = _safe_session(session)
    if steps is not None:
        output["steps"] = [serialize_agent_step(step, role=role) for step in list(steps)[:500]]
    if isinstance(live_state, Mapping):
        output["live_state"] = {
            key: live_state[key] for key in ("phase", "step_count", "max_steps", "current_tool")
            if key in live_state and isinstance(live_state[key], (str, int, float, bool))
        }
    return output


def serialize_chat_session(session: Mapping[str, Any], steps: Optional[Iterable[Mapping[str, Any]]] = None,
                           role: str = THREAT_HUNTER) -> dict[str, Any]:
    authorize_flow(role, "chat")
    return serialize_agent_session(session, steps=steps, role=THREAT_HUNTER if role == THREAT_HUNTER else ADMIN)


def serialize_tool_definition(tool: Any, role: str = THREAT_HUNTER) -> Optional[dict[str, Any]]:
    authorize_flow(role, "agent")
    if isinstance(tool, Mapping):
        name = tool.get("name")
        category = tool.get("category")
        dangerous = bool(tool.get("is_dangerous", False))
        description = tool.get("description", "")
        source = tool.get("source", "")
        requires_approval = bool(tool.get("requires_approval", False))
    else:
        name = getattr(tool, "name", None)
        category = getattr(tool, "category", None)
        dangerous = bool(getattr(tool, "is_dangerous", False))
        description = getattr(tool, "description", "")
        source = getattr(tool, "source", "")
        requires_approval = bool(getattr(tool, "requires_approval", False))
    if role != ADMIN and (dangerous or category in {"sandbox", "edr"}):
        return None
    if not isinstance(name, str) or not name:
        return None
    return {
        "name": name, "description": _text(description, 1000) or "",
        "source": _text(source, 200), "category": _text(category, 100),
        "requires_approval": requires_approval,
        "is_dangerous": dangerous,
    }


def is_tool_allowed(role: str, tool: Any) -> bool:
    """Return whether an agent role may discover and execute a tool."""
    if role not in {THREAT_HUNTER, ADMIN}:
        return False
    if role == ADMIN:
        return True
    if isinstance(tool, Mapping):
        category = tool.get("category")
        dangerous = bool(tool.get("is_dangerous", False))
    else:
        category = getattr(tool, "category", None)
        dangerous = bool(getattr(tool, "is_dangerous", False))
    return not dangerous and category not in {"sandbox", "edr"}


def serialize_playbook(playbook: Mapping[str, Any], role: str, *, detail: bool = False) -> dict[str, Any]:
    authorize_flow(role, "playbook")
    output = {
        key: playbook.get(key)
        for key in ("id", "name", "category", "description", "step_count", "source", "trigger_type")
        if playbook.get(key) is not None
    }
    if detail and role in {INCIDENT_RESPONDER, ADMIN}:
        output["steps"] = []
        if isinstance(playbook.get("steps"), list):
            for step in playbook["steps"][:100]:
                if isinstance(step, dict):
                    output["steps"].append({
                        key: _text(step.get(key), 1000)
                        for key in ("name", "tool", "description", "action", "condition")
                        if _text(step.get(key), 1000) is not None
                    })
    return output


def serialize_case(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    authorize_flow(role, "case")
    output = {
        key: case.get(key)
        for key in ("id", "title", "description", "severity", "status", "priority", "assignee",
                    "created_at", "updated_at", "analysis_count", "note_count")
        if case.get(key) is not None
    }
    if isinstance(case.get("analyses"), list):
        output["analyses"] = [
            {key: item.get(key) for key in ("analysis_id", "linked_at") if item.get(key) is not None}
            for item in case["analyses"][:500] if isinstance(item, dict)
        ]
    if isinstance(case.get("notes"), list):
        output["notes"] = [
            {key: _text(item.get(key), 4000) for key in ("id", "content", "author", "created_at") if item.get(key) is not None}
            for item in case["notes"][:500] if isinstance(item, dict)
        ]
    return output


def serialize_case_report(report: Mapping[str, Any], role: str) -> dict[str, Any]:
    authorize_flow(role, "case")
    allowed = ("case_id", "threat_type", "threat_description", "attacker_ip", "target_ip",
               "affected_username", "findings", "analysis", "impact", "remediation", "reference",
               "severity_4tier", "created_at", "updated_at")
    output = {}
    for key in allowed:
        value = report.get(key)
        if isinstance(value, list):
            output[key] = _scalar_list(value)
        elif isinstance(value, (str, int, float, bool)):
            output[key] = _text(value, 4000) if isinstance(value, str) else value
    return output


def serialize_websocket_frame(frame: Mapping[str, Any], *, role: str, flow: str) -> dict[str, Any]:
    """Serialize one outgoing WebSocket frame; unknown frames fail closed."""
    authorize_flow(role, flow)
    if not isinstance(frame, Mapping) or not isinstance(frame.get("type"), str):
        raise VisibilityError("Unknown WebSocket frame")
    frame_type = frame["type"]
    if flow == "websocket_analysis":
        if frame_type == "heartbeat":
            return {"type": "heartbeat"}
        if frame_type not in {"status", "completed", "failed", "progress"}:
            raise VisibilityError("Unknown analysis WebSocket frame")
        allowed = {"type", "status", "progress", "step", "verdict", "score"}
        return {key: frame[key] for key in allowed if key in frame and isinstance(frame[key], (str, int, float, bool))}
    if flow == "websocket_agent":
        if frame_type == "heartbeat":
            return {"type": "heartbeat"}
        if frame_type in {"completed", "failed", "cancelled"}:
            output = {"type": frame_type}
            if frame_type == "completed":
                output["summary"] = _text(frame.get("summary"), 4000) or ""
            elif frame_type == "failed":
                output["error"] = "Agent investigation failed"
            return output
        if frame_type in {"phase", "tool_call", "tool_result", "observation", "approval_required", "step"}:
            output = {"type": frame_type}
            for key in ("step", "max_steps", "duration", "duration_ms"):
                if key in frame and isinstance(frame[key], (str, int, float, bool)):
                    output[key] = frame[key]
            for key in ("phase", "tool", "tool_source", "tool_server"):
                if key in frame and isinstance(frame[key], str):
                    output[key] = frame[key][:200]
            if frame_type == "step" and isinstance(frame.get("step"), Mapping):
                output["step"] = serialize_agent_step(frame["step"], role=role)
            if frame_type == "approval_required":
                output["reason"] = _text(frame.get("reason"), 1000) or "Approval required"
            return output
        if frame_type == "session_state":
            session = frame.get("session")
            if not isinstance(session, Mapping):
                raise VisibilityError("Invalid agent session state")
            return {
                "type": "session_state",
                "session": serialize_agent_session(
                    session,
                    steps=frame.get("steps") if isinstance(frame.get("steps"), list) else None,
                    role=role,
                ),
            }
        raise VisibilityError("Unknown agent WebSocket frame")
    raise VisibilityError("WebSocket flow is not serializable")


def serialize_dashboard_stats(stats: Mapping[str, Any], role: str) -> dict[str, Any]:
    """Serialize dashboard counters from an allowlist of presentation fields."""
    authorize_flow(role, "dashboard")
    allowed = {
        "total_analyses", "completed_analyses", "failed_analyses", "running_analyses",
        "queued_analyses", "malicious_count", "suspicious_count", "clean_count",
        "average_score", "avg_score", "total_cases", "open_cases",
    }
    return {
        key: stats[key]
        for key in allowed
        if key in stats and isinstance(stats[key], (str, int, float, bool))
    }


def serialize_dashboard_sources(sources: Iterable[Mapping[str, Any]], role: str) -> list[dict[str, Any]]:
    """Serialize source health without provider configuration or payloads."""
    authorize_flow(role, "dashboard")
    output = []
    for source in list(sources)[:100]:
        if not isinstance(source, Mapping):
            continue
        row = {}
        for key in ("name", "status", "avg_response_ms"):
            value = source.get(key)
            if isinstance(value, (str, int, float, bool)):
                row[key] = _text(value, 200) if isinstance(value, str) else value
        if row:
            output.append(row)
    return output


def serialize_agent_stats(stats: Mapping[str, Any], role: str) -> dict[str, Any]:
    authorize_flow(role, "agent")
    allowed = {
        "active_sessions", "completed_sessions", "failed_sessions", "total_sessions",
        "registered_tools", "mcp_servers", "mcp_connected",
    }
    return {
        key: stats[key]
        for key in allowed
        if key in stats and isinstance(stats[key], (str, int, float, bool))
    }


def serialize_memory_stats(stats: Mapping[str, Any], role: str) -> dict[str, Any]:
    authorize_flow(role, "agent")
    return {
        str(key): value
        for key, value in stats.items()
        if isinstance(key, str) and isinstance(value, (str, int, float, bool))
        and key.lower() not in {"path", "file_path", "temp_path", "token", "password", "secret"}
    }


def serialize_sandbox_status(status: Any, role: str) -> list[dict[str, Any]]:
    authorize_flow(role, "agent")
    if not isinstance(status, list):
        return []
    output = []
    for item in status[:100]:
        if not isinstance(item, Mapping):
            continue
        row = {}
        for key in ("id", "status", "created_at", "updated_at", "owner_id"):
            value = item.get(key)
            if isinstance(value, (str, int, float, bool)):
                row[key] = value
        if row:
            output.append(row)
    return output


def serialize_audit_entries(entries: Iterable[Mapping[str, Any]], role: str) -> list[dict[str, Any]]:
    authorize_flow(role, "agent")
    allowed = ("id", "actor", "action", "action_type", "approved_by", "status", "timestamp", "created_at")
    output = []
    for entry in list(entries)[:200]:
        if not isinstance(entry, Mapping):
            continue
        row = {
            key: _text(entry.get(key), 500)
            for key in allowed
            if isinstance(entry.get(key), (str, int, float, bool))
        }
        if row:
            output.append(row)
    return output


def serialize_correlation(result: Any, role: str) -> dict[str, Any]:
    authorize_flow(role, "agent")
    if not isinstance(result, Mapping):
        return {}
    output = {}
    for key in (
        "total_findings",
        "correlated_groups",
        "confidence",
        "summary",
        "severity",
        "escalation_recommendations",
    ):
        value = result.get(key)
        if isinstance(value, (str, int, float, bool)):
            output[key] = _text(value, 2000) if isinstance(value, str) else value
        elif key == "escalation_recommendations" and isinstance(value, list) and all(
            isinstance(item, str) for item in value
        ):
            output[key] = [_text(item, 2000) for item in value]
    return output
