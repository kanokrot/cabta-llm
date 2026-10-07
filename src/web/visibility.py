"""Centralized, fail-closed response visibility policy."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Mapping, Optional


SOC = "SOC Analyst Tier 1-2"
INCIDENT_RESPONDER = "Incident Responder"
THREAT_HUNTER = "Threat Hunter"
TEAM_LEAD = "Team Lead"
ADMIN = "admin"

VALID_ROLES = frozenset({SOC, INCIDENT_RESPONDER, THREAT_HUNTER, TEAM_LEAD, ADMIN})
VALID_FLOWS = frozenset({
    "analysis", "dashboard", "report", "chat", "agent", "playbook", "case",
    "websocket_analysis", "websocket_agent", "websocket_playbook", "gmail", "gmail_admin",
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
    if flow == "websocket_playbook":
        return frozenset({INCIDENT_RESPONDER, ADMIN})
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


def can_access_playbook_session(user: Mapping[str, Any], session: Mapping[str, Any]) -> bool:
    """Central session access rule for agent and playbook session workflows."""
    if not isinstance(user, Mapping) or not isinstance(session, Mapping):
        return False
    role = user.get("role")
    if role == ADMIN:
        return True

    user_id = user.get("id")
    owner_id = session.get("user_id")
    if user_id is None or owner_id is None or str(user_id) != str(owner_id):
        return False

    if role == INCIDENT_RESPONDER:
        return _as_dict(session.get("metadata")).get("kind") == "playbook"
    if role == THREAT_HUNTER:
        return True
    return False


_FILE_RESULT_SENSITIVE_KEYS = {
    "path", "file_path", "temp_path", "token", "password",
    "secret", "credential", "credentials", "api_key",
    "provider_payload", "raw_source",
}
_FILE_RESULT_OMIT = object()


def _safe_file_result_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        output = {}
        for key, item in list(value.items())[:200]:
            if not isinstance(key, str) or key.lower() in _FILE_RESULT_SENSITIVE_KEYS:
                continue
            safe_item = _safe_file_result_value(item)
            if safe_item is not _FILE_RESULT_OMIT:
                output[key[:200]] = safe_item
        return output
    if isinstance(value, (list, tuple)):
        output = []
        for item in list(value)[:100]:
            safe_item = _safe_file_result_value(item)
            if safe_item is not _FILE_RESULT_OMIT:
                output.append(safe_item)
        return output
    if isinstance(value, str):
        return value[:20000]
    if isinstance(value, (int, float, bool)):
        return value
    return _FILE_RESULT_OMIT


_EMAIL_RESULT_SENSITIVE_KEYS = {
    "path", "file_path", "temp_path", "token", "password",
    "secret", "credential", "credentials", "api_key",
    "provider_payload", "raw_source",
}
_EMAIL_RESULT_DROP_KEYS = {
    "body_text", "body_html", "raw_output", "raw_response",
    "data", "base64", "provider_payload",
}
_EMAIL_RESULT_OMIT = object()


def _safe_email_result_value(value: Any, *, _in_attachment: bool = False) -> Any:
    if isinstance(value, Mapping):
        output = {}
        for key, item in list(value.items())[:200]:
            if not isinstance(key, str):
                continue
            lowered_key = key.lower()
            if lowered_key in _EMAIL_RESULT_SENSITIVE_KEYS:
                continue
            if lowered_key in _EMAIL_RESULT_DROP_KEYS:
                continue
            if lowered_key == "content" and _in_attachment:
                continue
            safe_item = _safe_email_result_value(
                item,
                _in_attachment=_in_attachment or lowered_key == "attachments",
            )
            if safe_item is not _EMAIL_RESULT_OMIT:
                output[key[:200]] = safe_item
        return output
    if isinstance(value, (list, tuple)):
        output = []
        for item in list(value)[:100]:
            safe_item = _safe_email_result_value(item, _in_attachment=_in_attachment)
            if safe_item is not _EMAIL_RESULT_OMIT:
                output.append(safe_item)
        return output
    if isinstance(value, str):
        return value[:20000]
    if isinstance(value, (int, float, bool)):
        return value
    return _EMAIL_RESULT_OMIT


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


_DETAILED_SOURCE_KEYS = (
    "error", "message", "found", "not_applicable", "unavailable", "timeout",
    "cached", "cache_reason", "feed_status", "source", "source_id",
    "last_analysis", "pulses", "total_pulses", "qualified_pulses",
    "unique_attribution_count", "sources_checked", "sources_found", "is_c2",
    "malware_families", "c2_frameworks", "first_seen", "last_seen",
    "latest_event_timestamp", "cache_fetched_at", "last_successful_refresh",
    "consecutive_refresh_failures",
)
_DETAILED_SOURCE_LIST_KEYS = frozenset({
    "malware_families", "c2_frameworks", "sources_found",
})
_SENSITIVE_SOURCE_KEY_PARTS = ("key", "token", "secret", "password", "auth")


def _sanitize_source_text(value: str) -> str:
    value = re.sub(r"https?://\S+|www\.\S+", "[url]", value, flags=re.IGNORECASE)
    value = re.sub(
        r"(?i)\b(?:api[_-]?key|token|secret)\s*[:=]\s*\S+"
        r"|\bauthorization\s*:\s*\S+"
        r"|\bbearer\s+\S+",
        "[redacted]",
        value,
    )
    return re.sub(r"\s+", " ", value).strip()[:200]


def _safe_number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _safe_domain_enrichment(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    output: dict[str, Any] = {}
    domain_age = value.get("domain_age")
    if isinstance(domain_age, dict):
        safe_age: dict[str, Any] = {}
        for key, limit in (("domain", 253), ("creation_date", 40), ("risk_level", 20)):
            item = domain_age.get(key)
            if isinstance(item, str):
                safe_age[key] = item[:limit]
        age_days = domain_age.get("age_days")
        if isinstance(age_days, int) and not isinstance(age_days, bool):
            safe_age["age_days"] = age_days
        if isinstance(domain_age.get("is_newly_registered"), bool):
            safe_age["is_newly_registered"] = domain_age["is_newly_registered"]
        if isinstance(domain_age.get("error"), str):
            safe_age["error"] = _sanitize_source_text(domain_age["error"])[:120]
        if safe_age:
            output["domain_age"] = safe_age

    dga_analysis = value.get("dga_analysis")
    if isinstance(dga_analysis, dict):
        safe_dga: dict[str, Any] = {}
        for key, limit in (("domain", 253), ("sld", 253)):
            item = dga_analysis.get(key)
            if isinstance(item, str):
                safe_dga[key] = item[:limit]
        for key in ("entropy", "consonant_ratio", "ngram_score", "confidence"):
            number = _safe_number(dga_analysis.get(key))
            if number is not None:
                safe_dga[key] = number
        if isinstance(dga_analysis.get("is_dga"), bool):
            safe_dga["is_dga"] = dga_analysis["is_dga"]
        family = dga_analysis.get("dga_family_guess")
        if isinstance(family, str):
            safe_dga["dga_family_guess"] = family[:40]

        dictionary_match = dga_analysis.get("dictionary_match")
        if isinstance(dictionary_match, dict):
            safe_dictionary: dict[str, Any] = {}
            for key in ("coverage", "word_count"):
                number = _safe_number(dictionary_match.get(key))
                if number is not None:
                    safe_dictionary[key] = number
            words_found = dictionary_match.get("words_found")
            if isinstance(words_found, list):
                safe_dictionary["words_found"] = [
                    word[:30] for word in words_found[:10] if isinstance(word, str)
                ]
            if safe_dictionary:
                safe_dga["dictionary_match"] = safe_dictionary
        if safe_dga:
            output["dga_analysis"] = safe_dga

    return output


def _safe_sources(value: Any, *, detailed: bool = False) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, dict[str, Any]] = {}
    for source_name, source_value in list(value.items())[:100]:
        if not isinstance(source_name, str) or not isinstance(source_value, dict):
            continue
        row = {}
        allowed_keys = ("status", "score", "confidence", "detections", "total_engines")
        if detailed:
            allowed_keys += _DETAILED_SOURCE_KEYS
        for key in allowed_keys:
            if any(part in key.lower() for part in _SENSITIVE_SOURCE_KEY_PARTS):
                continue
            if key not in source_value:
                continue
            item = source_value[key]
            if isinstance(item, str):
                row[key] = (
                    _sanitize_source_text(item)
                    if key in {"error", "message"}
                    else item[:300]
                )
            elif isinstance(item, (int, float, bool)):
                row[key] = item
            elif key in _DETAILED_SOURCE_LIST_KEYS and isinstance(item, list):
                row[key] = [
                    entry[:100] if isinstance(entry, str) else entry
                    for entry in item[:20]
                    if isinstance(entry, (str, int, float, bool))
                ]
        if not detailed:
            error_value = source_value.get("error")
            if isinstance(error_value, str):
                http_match = re.search(r"\bHTTP\s+(\d{3})\b", error_value)
                if http_match:
                    http_status = int(http_match.group(1))
                    if 100 <= http_status <= 599:
                        row["http_status"] = http_status
            if source_value.get("feed_status") == "unavailable":
                row["feed_status"] = "unavailable"
        if row:
            output[source_name[:100]] = row
    return output


def _safe_extra_evidence(value: Any) -> list[dict[str, Any]]:
    """Allow only compact summaries from post-score user-key cross-checks."""
    if not isinstance(value, list):
        return []
    allowed_fields = {
        "virustotal": {"malicious", "suspicious", "total_engines"},
        "abuseipdb": {"confidence", "reports", "country"},
        "otx": {"pulses", "reputation"},
    }
    allowed_statuses = {"available", "not_found", "not_applicable", "unavailable"}
    output = []
    for item in value[:3]:
        if not isinstance(item, Mapping):
            continue
        source = item.get("source")
        status = item.get("status")
        if (
            not isinstance(source, str)
            or not isinstance(status, str)
            or source not in allowed_fields
            or status not in allowed_statuses
        ):
            continue
        row: dict[str, Any] = {"source": source, "status": status}
        summary = item.get("summary")
        if isinstance(summary, Mapping):
            safe_summary = {}
            for key in allowed_fields[source]:
                value_item = summary.get(key)
                if isinstance(value_item, str):
                    safe_summary[key] = value_item[:80]
                elif isinstance(value_item, (int, float)) and not isinstance(value_item, bool):
                    safe_summary[key] = value_item
            if safe_summary:
                row["summary"] = safe_summary
        output.append(row)
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


def _safe_ai_status(value: Any) -> Optional[str]:
    if isinstance(value, str) and value in {"disabled", "complete", "failed"}:
        return value
    return None


def _safe_ai_error(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned_text = " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value).split())
    return cleaned_text[:300] or None


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
    ai_status = _safe_ai_status(result.get("ai_status"))
    if ai_status is not None:
        output["ai_status"] = ai_status
    if detailed:
        ai_error = _safe_ai_error(result.get("ai_error"))
        if ai_error is not None:
            output["ai_error"] = ai_error
    if isinstance(result.get("sources"), dict):
        output["sources"] = _safe_sources(result["sources"], detailed=detailed)
    if "extra_evidence" in result:
        output["extra_evidence"] = _safe_extra_evidence(result.get("extra_evidence"))
    llm_analysis = result.get("llm_analysis")
    if isinstance(llm_analysis, dict) and any(
        isinstance(llm_analysis.get(key), str) for key in ("verdict", "analysis")
    ):
        safe_llm_analysis = {}
        if isinstance(llm_analysis.get("verdict"), str):
            safe_llm_analysis["verdict"] = llm_analysis["verdict"][:20]
        if isinstance(llm_analysis.get("analysis"), str):
            safe_llm_analysis["analysis"] = llm_analysis["analysis"][:2000]
        if isinstance(llm_analysis.get("recommendations"), list):
            safe_llm_analysis["recommendations"] = _scalar_list(
                llm_analysis["recommendations"]
            )
        if isinstance(llm_analysis.get("hallucination_warning"), str):
            safe_llm_analysis["hallucination_warning"] = llm_analysis[
                "hallucination_warning"
            ][:500]
        output["llm_analysis"] = safe_llm_analysis
    if isinstance(result.get("recommendations"), list):
        output["recommendations"] = _scalar_list(result["recommendations"])
    if isinstance(result.get("recommendations_rule_based"), list):
        output["recommendations_rule_based"] = _scalar_list(
            result["recommendations_rule_based"]
        )
    if result.get("recommendations_source") in {"llm", "rule_based"}:
        output["recommendations_source"] = result["recommendations_source"]
    safe_domain_enrichment = _safe_domain_enrichment(result.get("domain_enrichment"))
    if safe_domain_enrichment:
        output["domain_enrichment"] = safe_domain_enrichment
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
    for key in ("sources_checked", "sources_flagged"):
        value = result.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            output[key] = value
    if job.get("analysis_type") == "file":
        for key in (
            "entropy_analysis",
            "static_analysis",
            "capabilities",
            "detection_rules",
        ):
            if key in result:
                safe_value = _safe_file_result_value(result[key])
                if safe_value is not _FILE_RESULT_OMIT:
                    output[key] = safe_value
    elif job.get("analysis_type") == "ioc":
        if "extra_evidence" in result:
            output["extra_evidence"] = _safe_extra_evidence(
                result.get("extra_evidence")
            )
    elif job.get("analysis_type") == "email":
        detailed = role in {INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN}
        if detailed:
            email_data_raw = result.get("email_data")
            if isinstance(email_data_raw, dict):
                safe_email_data = {}
                for key in (
                    "spf", "dkim", "dmarc", "urls", "ips", "domains",
                    "from", "from_domain", "to", "subject", "date", "reply_to", "attachments",
                ):
                    if key not in email_data_raw:
                        continue
                    if key == "attachments":
                        attachments_raw = email_data_raw[key]
                        if isinstance(attachments_raw, (list, tuple)):
                            safe_attachments = []
                            for attachment in list(attachments_raw)[:100]:
                                if not isinstance(attachment, Mapping):
                                    continue
                                safe_attachment = {}
                                for attachment_key in ("filename", "content_type", "size"):
                                    if attachment_key not in attachment:
                                        continue
                                    safe_value = _safe_email_result_value(
                                        attachment[attachment_key],
                                        _in_attachment=True,
                                    )
                                    if safe_value is not _EMAIL_RESULT_OMIT:
                                        safe_attachment[attachment_key] = safe_value
                                safe_attachments.append(safe_attachment)
                            safe_email_data[key] = safe_attachments
                        continue
                    safe_value = _safe_email_result_value(email_data_raw[key])
                    if safe_value is not _EMAIL_RESULT_OMIT:
                        safe_email_data[key] = safe_value
                advanced_analysis_raw = result.get("advanced_analysis")
                if isinstance(advanced_analysis_raw, Mapping):
                    header_analysis = advanced_analysis_raw.get("header_analysis")
                    if isinstance(header_analysis, Mapping):
                        safe_value = _safe_email_result_value(header_analysis)
                        if safe_value is not _EMAIL_RESULT_OMIT:
                            safe_email_data["headers"] = safe_value
                if safe_email_data:
                    output["email_data"] = safe_email_data
            for key in (
                "composite_score", "base_phishing_score", "forensics",
                "advanced_analysis", "detection_rules", "llm_analysis", "iocs_found",
                "capability_errors",
            ):
                if key in result:
                    safe_value = _safe_email_result_value(result[key])
                    if safe_value is not _EMAIL_RESULT_OMIT:
                        output[key] = safe_value
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


def serialize_report_job(
    job: Dict[str, Any],
    role: str = SOC,
    viewer_user_id: int | None = None,
) -> Dict[str, Any]:
    authorize_flow(role, "report")
    detailed = role in {INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN} or (
        viewer_user_id is not None and job.get("user_id") == viewer_user_id
    )
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
    params = job.get("params")
    if not isinstance(params, Mapping):
        params = {}
    steps = []
    for raw_step in params.get("_analysis_steps", []):
        if not isinstance(raw_step, Mapping):
            continue
        key = _text(raw_step.get("key"), 100)
        label = _text(raw_step.get("label"), 200)
        state = _text(raw_step.get("state"), 20)
        if not key or not label or state not in {
            "pending", "started", "completed", "skipped", "failed"
        }:
            continue
        steps.append({"key": key, "label": label, "state": state})
    steps_done = sum(
        step["state"] in {"completed", "skipped"} for step in steps
    )
    return {
        "analysis_id": job.get("id"), "status": job.get("status"),
        "progress": job.get("progress", 0),
        "current_step": _text(job.get("current_step", ""), 200),
        "verdict": job.get("verdict"), "score": job.get("score"),
        "steps": steps,
        "steps_total": len(steps),
        "steps_done": steps_done,
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


def _agent_history_content(step: Mapping[str, Any]) -> Optional[str]:
    raw_content = _text(step.get("content"), 4000)
    if raw_content is None:
        return None
    if step.get("step_type") != "final_answer":
        return raw_content
    try:
        decision = json.loads(raw_content)
    except (TypeError, json.JSONDecodeError):
        return raw_content
    if isinstance(decision, Mapping):
        return _text(decision.get("answer"), 4000)
    return raw_content


def _agent_history_verdict(step: Mapping[str, Any]) -> Optional[str]:
    if step.get("step_type") != "final_answer":
        return None
    raw_content = _text(step.get("content"), 4000)
    if raw_content is None:
        return None
    try:
        decision = json.loads(raw_content)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(decision, Mapping):
        return None
    verdict = decision.get("verdict")
    if not isinstance(verdict, str):
        return None
    normalized = verdict.strip().upper()
    if normalized in {"MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"}:
        return normalized
    return None


def serialize_agent_session(session: Mapping[str, Any], steps: Optional[Iterable[Mapping[str, Any]]] = None,
                            live_state: Optional[Mapping[str, Any]] = None, role: str = THREAT_HUNTER) -> dict[str, Any]:
    authorize_flow(role, "agent")
    output = _safe_session(session)
    metadata = session.get("metadata")
    output["has_report"] = (
        bool(metadata.get("ioc_investigation_result"))
        if isinstance(metadata, Mapping) else False
    )
    history = []
    goal = _text(session.get("goal"), 4000)
    if goal:
        history.append({"role": "user", "content": goal})
    if steps is not None:
        raw_steps = list(steps)[:500]
        output["steps"] = [serialize_agent_step(step, role=role) for step in raw_steps]
        ordered_steps = sorted(
            raw_steps,
            key=lambda step: step.get("step_number")
            if isinstance(step.get("step_number"), (int, float)) else float("inf"),
        )
        for step in ordered_steps:
            if step.get("step_type") not in {"final_answer", "error"}:
                continue
            content = _agent_history_content(step)
            if content is not None:
                history_item = {"role": "agent", "content": content}
                verdict = _agent_history_verdict(step)
                if verdict is not None:
                    history_item["verdict"] = verdict
                history.append(history_item)
    output["history"] = history
    if isinstance(live_state, Mapping):
        output["live_state"] = {
            key: live_state[key] for key in ("phase", "step_count", "max_steps", "current_tool")
            if key in live_state and isinstance(live_state[key], (str, int, float, bool))
        }
    return output


def serialize_chat_session(session: Mapping[str, Any], steps: Optional[Iterable[Mapping[str, Any]]] = None,
                           role: str = THREAT_HUNTER) -> dict[str, Any]:
    authorize_flow(role, "chat")
    if role == INCIDENT_RESPONDER:
        raise VisibilityError("Incident Responders must use playbook session detail")
    return serialize_agent_session(session, steps=steps, role=role)


def serialize_playbook_session_detail(
    session: Mapping[str, Any],
    steps: Optional[Iterable[Mapping[str, Any]]] = None,
    *,
    role: str,
) -> dict[str, Any]:
    """Return a bounded playbook session view without raw execution data."""
    authorize_flow(role, "playbook")
    metadata = _as_dict(session.get("metadata"))
    kind = metadata.get("kind")
    if role == INCIDENT_RESPONDER and kind != "playbook":
        raise VisibilityError("Session is not a playbook session")

    output = {
        key: session.get(key)
        for key in (
            "id", "status", "goal", "summary", "created_at", "updated_at", "playbook_id",
        )
        if isinstance(session.get(key), (str, int, float, bool))
    }
    output["kind"] = kind if isinstance(kind, str) and kind in {"playbook", "agent"} else "unknown"
    output["has_report"] = bool(metadata.get("ioc_investigation_result"))
    if steps is not None:
        output["steps"] = [
            _serialize_playbook_step(step)
            for step in list(steps)[:500]
            if isinstance(step, Mapping)
        ]
    return output


def _serialize_playbook_step(step: Mapping[str, Any]) -> dict[str, Any]:
    output = {
        key: step[key]
        for key in (
            "id", "step_number", "step_type", "tool_name", "status",
            "duration_ms", "timestamp",
        )
        if key in step and isinstance(step[key], (str, int, float, bool))
    }
    summary = _text(step.get("content"), 2000)
    if summary is not None:
        output["summary"] = summary
    return output


def serialize_tool_definition(tool: Any, role: str = THREAT_HUNTER) -> Optional[dict[str, Any]]:
    from src.agent.mcp_tool_presentation import get_mcp_tool_presentation
    from src.agent.local_tool_presentation import get_local_tool_presentation

    unavailable_summary = "Tool description is not available from the registered metadata."

    authorize_flow(role, "agent")
    if isinstance(tool, Mapping):
        name = tool.get("name")
        category = tool.get("category")
        dangerous = bool(tool.get("is_dangerous", False))
        description = tool.get("description", "")
        source = tool.get("source", "")
        requires_approval = bool(tool.get("requires_approval", False))
        display_name = tool.get("display_name")
        ui_category = tool.get("ui_category")
        icon = tool.get("icon")
        summary = tool.get("summary")
        examples = tool.get("examples")
        logo = tool.get("logo")
        input_schema = tool.get("inputSchema", tool.get("parameters", {}))
    else:
        name = getattr(tool, "name", None)
        category = getattr(tool, "category", None)
        dangerous = bool(getattr(tool, "is_dangerous", False))
        description = getattr(tool, "description", "")
        source = getattr(tool, "source", "")
        requires_approval = bool(getattr(tool, "requires_approval", False))
        display_name = getattr(tool, "display_name", None)
        ui_category = getattr(tool, "ui_category", None)
        icon = getattr(tool, "icon", None)
        summary = getattr(tool, "summary", None)
        examples = getattr(tool, "examples", None)
        logo = getattr(tool, "logo", None)
        input_schema = getattr(tool, "inputSchema", getattr(tool, "parameters", {}))
    if role != ADMIN and (dangerous or category in {"sandbox", "edr"}):
        return None
    if not isinstance(name, str) or not name:
        return None
    raw_tool_name = name.rsplit(".", 1)[-1] if isinstance(source, str) and source != "local" else name
    presentation = get_mcp_tool_presentation(
        source,
        raw_tool_name,
        category if isinstance(category, str) else "",
    )
    local_presentation = (
        get_local_tool_presentation(name) if source == "local" else None
    )
    if local_presentation is not None:
        display_name = display_name or local_presentation.display_name
        icon = icon or local_presentation.icon
        ui_category = local_presentation.ui_category or ui_category
    else:
        display_name = display_name or presentation.display_name
        icon = icon or presentation.icon
    ui_category = ui_category or presentation.ui_category
    if source == "local":
        # Local ToolDefinition currently has no separate summary field.  Do not
        # expose the MCP presentation fallback when a local description exists.
        if not summary or summary == unavailable_summary:
            summary = description
    else:
        summary = summary or presentation.summary
    examples = examples or list(presentation.examples)
    logo = logo or presentation.logo
    if not isinstance(input_schema, Mapping):
        input_schema = {}
    if not isinstance(examples, list):
        examples = list(examples) if isinstance(examples, (tuple, set)) else list(presentation.examples)
    return {
        "name": name, "description": _text(description, 1000) or "",
        "source": _text(source, 200), "category": _text(category, 100),
        "requires_approval": requires_approval,
        "is_dangerous": dangerous,
        "display_name": _text(display_name, 200) or name,
        "ui_category": _text(ui_category, 100) or "Malware",
        "icon": _text(icon, 100) or "malware",
        "summary": _text(summary, 1000) or ("" if source == "local" else unavailable_summary),
        "examples": [_text(item, 300) for item in examples[:4] if isinstance(item, str)],
        "logo": _text(logo, 300) if isinstance(logo, str) else None,
        "inputSchema": input_schema,
    }


def is_tool_allowed(role: str, tool: Any) -> bool:
    """Return whether an agent role may discover and execute a tool."""
    if role not in {INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN}:
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
    steps = playbook.get("steps")
    if not isinstance(steps, list):
        steps = playbook.get("steps_json")
        if isinstance(steps, str):
            try:
                steps = json.loads(steps)
            except (TypeError, json.JSONDecodeError):
                steps = []
    if not isinstance(steps, list):
        steps = []

    output = {
        key: playbook.get(key)
        for key in ("id", "name", "category", "description", "step_count", "source", "trigger_type")
        if playbook.get(key) is not None
    }
    if not detail:
        output["tools"] = sorted({
            tool.strip()
            for step in steps
            if isinstance(step, Mapping)
            and isinstance((tool := step.get("tool")), str)
            and tool.strip()
        })
    if detail and role in {INCIDENT_RESPONDER, ADMIN}:
        from src.agent.mcp_tool_presentation import MCP_TOOL_PRESENTATION

        output["steps"] = []
        playbook_tools: set[str] = set()
        if isinstance(playbook.get("steps"), list):
            for step in playbook["steps"][:100]:
                if isinstance(step, dict):
                    safe_step = {
                        key: _text(step.get(key), 1000)
                        for key in ("name", "tool", "description", "action")
                        if _text(step.get(key), 1000) is not None
                    }
                    output["steps"].append(safe_step)
                    tool_name = step.get("tool")
                    if isinstance(tool_name, str) and tool_name.strip():
                        playbook_tools.add(tool_name.strip())

        input_params = playbook.get("input_params")
        if not isinstance(input_params, list):
            input_params = playbook.get("input")
        safe_params = []
        if isinstance(input_params, list):
            for param in input_params[:100]:
                if not isinstance(param, Mapping) or not isinstance(param.get("name"), str):
                    continue
                safe_param: dict[str, Any] = {
                    "name": _text(param.get("name"), 200) or "",
                    "required": bool(param.get("required", False)),
                    "type": _text(param.get("type"), 100) if isinstance(param.get("type"), str) else None,
                    "description": _text(param.get("description"), 1000)
                    if isinstance(param.get("description"), str) else None,
                    "example": param.get("example"),
                }
                safe_params.append(safe_param)
        output["input_params"] = safe_params
        overview = playbook.get("overview")
        output["overview"] = [
            _text(item, 500) or ""
            for item in overview[:50]
            if isinstance(item, str)
        ] if isinstance(overview, list) else []
        output_text = playbook.get("output")
        output["output"] = _text(output_text, 4000) or "" if isinstance(output_text, str) else ""
        output["approval_steps"] = sum(
            1 for step in steps
            if isinstance(step, Mapping) and step.get("requires_approval") is True
        )

        def display_label(value: str) -> str:
            acronyms = {
                "ioc": "IOC", "osint": "OSINT", "url": "URL", "pe": "PE",
                "remnux": "REMnux", "whois": "WHOIS", "dns": "DNS", "ip": "IP",
                "ssl": "SSL", "cve": "CVE", "epss": "EPSS", "apk": "APK",
                "yara": "YARA", "mcp": "MCP",
            }
            return " ".join(
                acronyms.get(part.lower(), part[:1].upper() + part[1:].lower())
                for part in re.split(r"[_-]+", value.strip()) if part
            )

        tool_display = {}
        for tool_id in sorted(playbook_tools):
            if not tool_id.startswith("mcp:") or "/" not in tool_id[4:]:
                continue
            server_id, raw_name = tool_id[4:].split("/", 1)
            presentation = MCP_TOOL_PRESENTATION.get((server_id, raw_name))
            tool_display[tool_id] = {
                "display_name": presentation.display_name if presentation else display_label(raw_name),
                "server_display_name": display_label(
                    server_id[:-6] if server_id.endswith("_tools") else server_id
                ),
            }
        output["tool_display"] = tool_display
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
               "affected_username", "attack_outcome", "occurrence_note", "detected_at",
               "detection_device", "findings", "analysis", "impact", "remediation", "reference",
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
    if flow == "websocket_playbook":
        if frame_type == "heartbeat":
            return {"type": "heartbeat"}
        if frame_type in {"completed", "failed", "cancelled"}:
            output = {"type": frame_type}
            if frame_type == "completed":
                output["summary"] = _text(frame.get("summary"), 4000) or ""
            elif frame_type == "failed":
                output["error"] = "Playbook execution failed"
            return output
        if frame_type == "session_state":
            session = frame.get("session")
            if not isinstance(session, Mapping):
                raise VisibilityError("Invalid playbook session state")
            return {
                "type": "session_state",
                "session": serialize_playbook_session_detail(
                    session,
                    steps=frame.get("steps") if isinstance(frame.get("steps"), list) else None,
                    role=role,
                ),
            }
        if frame_type == "approval_required":
            output = {"type": frame_type}
            step = frame.get("step")
            if isinstance(step, (str, int, float, bool)):
                output["step"] = step
            for key in ("tool", "action"):
                if isinstance(frame.get(key), str):
                    output[key] = frame[key][:200]
            output["description"] = _text(
                frame.get("description", frame.get("reason")), 1000
            ) or "Approval required"
            if "params" in frame:
                output["params"] = _safe_approval_params(frame["params"])
            return output
        if frame_type in {"phase", "tool_call", "tool_result", "step"}:
            output = {"type": frame_type}
            for key in ("step", "duration", "duration_ms", "max_steps"):
                if key in frame and isinstance(frame[key], (str, int, float, bool)):
                    output[key] = frame[key]
            for key in ("phase", "tool"):
                if isinstance(frame.get(key), str):
                    output[key] = frame[key][:200]
            if frame_type == "step" and isinstance(frame.get("step"), Mapping):
                output["step"] = _serialize_playbook_step(frame["step"])
            return output
        raise VisibilityError("Unknown playbook WebSocket frame")
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
                description = frame.get("description")
                if isinstance(description, str):
                    output["description"] = description[:300]
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
        "phishing_count", "spam_count", "unknown_count",
        "daily_counts", "score_buckets", "country_covered",
    }
    output = {
        key: stats[key]
        for key in allowed
        if key in stats and isinstance(stats[key], (str, int, float, bool))
    }
    daily_counts = stats.get("daily_counts")
    if isinstance(daily_counts, list):
        output["daily_counts"] = [
            {
                "date": item["date"],
                "malicious": item["malicious"],
                "suspicious": item["suspicious"],
                "clean": item["clean"],
            }
            for item in daily_counts
            if isinstance(item, Mapping)
            and isinstance(item.get("date"), str)
            and all(isinstance(item.get(group), int) for group in (
                "malicious", "suspicious", "clean",
            ))
        ]
    score_buckets = stats.get("score_buckets")
    if isinstance(score_buckets, list):
        output["score_buckets"] = [
            {"label": item["label"], "count": item["count"]}
            for item in score_buckets
            if isinstance(item, Mapping)
            and isinstance(item.get("label"), str)
            and isinstance(item.get("count"), int)
        ]
    country_stats = stats.get("country_stats")
    if isinstance(country_stats, list):
        serialized_countries = []
        valid_verdicts = {"MALICIOUS", "SUSPICIOUS", "CLEAN", "PHISHING", "SPAM", "UNKNOWN"}
        for item in country_stats:
            if not isinstance(item, Mapping):
                continue
            code = item.get("code")
            worst_verdict = item.get("worst_verdict")
            ips = item.get("ips")
            analyses = item.get("analyses")
            if (
                not isinstance(code, str)
                or len(code) != 2
                or not code.isascii()
                or not code.isalpha()
                or not isinstance(ips, int)
                or isinstance(ips, bool)
                or not isinstance(analyses, int)
                or isinstance(analyses, bool)
                or not isinstance(worst_verdict, str)
                or worst_verdict.upper() not in valid_verdicts
            ):
                continue
            serialized_countries.append({
                "code": code.upper(),
                "ips": ips,
                "analyses": analyses,
                "worst_verdict": worst_verdict.upper(),
            })
        serialized_countries.sort(
            key=lambda item: (-item["ips"], -item["analyses"], item["code"])
        )
        output["country_stats"] = serialized_countries[:50]
    return output


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


def _safe_approval_params(value: Any, *, depth: int = 0) -> Any:
    """Bound approval parameters before they are shown to a human approver."""
    if depth > 5:
        return "[maximum nesting depth reached]"
    if isinstance(value, Mapping):
        output = {}
        for key, item in list(value.items())[:100]:
            if isinstance(key, str):
                output[key[:500]] = _safe_approval_params(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [_safe_approval_params(item, depth=depth + 1) for item in list(value)[:100]]
    if isinstance(value, str):
        return value[:500]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return None


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
