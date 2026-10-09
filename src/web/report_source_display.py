"""Display-only formatting for source rows in HTML reports.

Classification and counters are computed by the report template. Functions in
this module only consume that precomputed class and format values for display.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from ..scoring.intelligent_scoring import SOURCE_SCORING_MULTIPLIERS
from .source_classification import classify_source


SOURCE_LABELS = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "shodan": "Shodan",
    "alienvault": "AlienVault",
    "urlhaus": "URLhaus",
    "feodotracker": "Feodo Tracker",
    "threatfox": "ThreatFox",
    "malwarebazaar": "MalwareBazaar",
    "c2_trackers": "C2 Trackers",
    "tor_exit_nodes": "Tor Exit Nodes",
    "sslblacklist": "SSL Blacklist",
    "smet_nrd": "Smet NRD",
    "hagezi_nrd": "HaGeZi NRD",
    "mb_recent_sha256": "MalwareBazaar Recent SHA256",
    "misp_circl_feed_osint": "MISP CIRCL feed",
    "usom": "USOM",
    "greynoise": "GreyNoise",
    "censys": "Censys",
    "talos": "Talos",
    "pulsedive": "Pulsedive",
    "criminalip": "Criminal IP",
    "ipqualityscore": "IPQualityScore",
    "spamhaus": "Spamhaus",
    "phishtank": "PhishTank",
    "circl": "CIRCL",
    "ip2proxy": "IP2Proxy",
    "triage": "Triage",
    "threatzone": "Threat.Zone",
}

SUMMARY_FIELDS = {
    "threatfox": ("confidence", "first_seen", "threat_type"),
    "virustotal": ("detections", "last_analysis", "message"),
    "alienvault": ("pulses", "total_pulses", "qualified_pulses"),
    "c2_trackers": ("sources_checked", "is_c2", "first_seen", "last_seen"),
    "circl": ("records", "message"),
    "misp_circl_feed_osint": ("feed_status", "message"),
    "smet_nrd": ("message",),
    "hagezi_nrd": ("message",),
    "pulsedive": ("risk", "threats", "stamp_seen"),
    "abuseipdb": ("confidence", "reports"),
    "shodan": ("is_c2", "vulns", "ports"),
    "urlhaus": ("threat", "tags", "message"),
    "feodotracker": ("botnet", "first_seen", "last_seen"),
    "malwarebazaar": ("signature", "file_type", "message"),
    "tor_exit_nodes": ("is_tor",),
    "sslblacklist": ("message",),
    "mb_recent_sha256": ("message",),
    "usom": ("message",),
    "greynoise": ("classification", "name", "last_seen"),
    "censys": ("autonomous_system", "location", "services"),
    "talos": ("sbrs_score", "message"),
    "criminalip": ("country", "is_proxy", "is_vpn"),
    "ipqualityscore": ("fraud_score", "proxy", "vpn"),
    "spamhaus": ("listed",),
    "phishtank": ("verified", "phish_id"),
    "ip2proxy": ("is_proxy", "proxy_type", "country"),
    "triage": ("family", "sample_id", "signatures"),
    "threatzone": ("verdict", "threat_level", "malware_family"),
}

_SUMMARY_META_FIELDS = {"status", "score", "not_applicable", "source", "source_id"}
_SCORE_PATTERN = re.compile(r"\b(\d+(?:\.\d+)?)\b")


def display_source_name(source_name: Any) -> str:
    """Return the explicit source label or a readable fallback for a raw key."""
    key = str(source_name)
    return SOURCE_LABELS.get(key.lower(), key.replace("_", " ").title())


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict, set)):
        return not value
    return False


def _is_summary_empty(value: Any) -> bool:
    return _is_empty(value) or value is False


def _compact_value(value: Any) -> str:
    if isinstance(value, (Mapping, list, tuple, set)):
        if isinstance(value, set):
            value = sorted(value, key=str)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    if isinstance(value, bool):
        return "True" if value else "False"
    return str(value)


def _score_value(source_data: Mapping[str, Any]) -> float | None:
    value = source_data.get("score")
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        match = _SCORE_PATTERN.search(str(value))
        return float(match.group(1)) if match else None


def _score_level(score: float) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def display_source_status(
    source_class: str,
    raw_status: Any,
    score: float | None,
    *,
    source_name: str = "",
    source_data: Mapping[str, Any] | None = None,
    ioc_type: str = "",
) -> str:
    """Map a raw status to a visible word badge without changing its class."""
    if source_class == "na":
        return "N/A"
    if source_class == "error":
        return "Error"
    if source_class == "flagged":
        return "Flagged"
    status = str(raw_status or "").strip()
    if status in {"\u2796", "not_applicable"}:
        return "N/A"
    if status == "\u23f3":
        return "Pending"
    if status == "\u26a0":
        return "Warning"
    if status in {"\u2713", "\u2717"}:
        if score is not None and score > 0:
            return {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}[_score_level(score)]
        if source_class == "clean":
            return "Clean"
        return "Responded" if status == "\u2713" else "Not found"
    if source_class == "clean":
        return "Clean"
    return status.title() if status else "Unknown"


def _humanize(key: Any) -> str:
    return str(key).replace("_", " ").strip()


def _summary_parts(
    source_name: str,
    source_data: Mapping[str, Any],
    source_class: str,
) -> tuple[str, set[str]]:
    used_keys: set[str] = set()

    if source_class == "error":
        error = source_data.get("error")
        message = source_data.get("message")
        feed_status = source_data.get("feed_status")
        reason = error if not _is_empty(error) else message
        parts = []
        if source_name.lower() == "misp_circl_feed_osint" and not _is_empty(feed_status):
            parts.append(f"feed status {_compact_value(feed_status)}")
            used_keys.add("feed_status")
        if not _is_empty(reason):
            parts.append(_compact_value(reason))
            used_keys.add("error" if reason is error else "message")
        elif not parts and not _is_empty(feed_status):
            parts.append(f"feed status {_compact_value(feed_status)}")
            used_keys.add("feed_status")
        text = " / ".join(parts) or "Source unavailable"
        if re.search(r"\bHTTP\s+401\b", text, re.IGNORECASE) and "check API credentials" not in text.lower():
            text += " - check API credentials"
        elif re.search(r"\bHTTP\s+403\b", text, re.IGNORECASE) and "check API credentials" not in text.lower():
            text += " - check API credentials"
        return text, used_keys

    message = source_data.get("message")
    fields = SUMMARY_FIELDS.get(source_name.lower())
    checked_count_fields = [
        (key, value)
        for key, value in source_data.items()
        if str(key).lower() in {
            "sources_checked", "feeds_checked", "checks_checked",
            "checked_count", "total_checked",
        }
        and not _is_summary_empty(value)
    ]
    if fields is None:
        selected = [
            (key, value)
            for key, value in source_data.items()
            if key not in _SUMMARY_META_FIELDS and not _is_summary_empty(value)
        ]
    else:
        selected = [
            (key, source_data.get(key))
            for key in fields
            if key in source_data
            and (
                not _is_summary_empty(source_data.get(key))
                or (
                    source_name.lower() == "c2_trackers"
                    and key == "is_c2"
                    and isinstance(source_data.get(key), bool)
                )
            )
        ]
    checked_count_keys = {str(key) for key, _ in checked_count_fields}
    selected = checked_count_fields[:3] + [
        (key, value) for key, value in selected
        if str(key) not in checked_count_keys
    ][:3 - min(3, len(checked_count_fields))]

    if source_class == "clean":
        has_checked_count = bool(checked_count_fields)
        if not has_checked_count and not _is_empty(message):
            message_text = _compact_value(message)
            if any(phrase in message_text.lower() for phrase in ("not found", "not listed", "no match", "no threat")):
                return message_text, {"message"}
        if not has_checked_count and source_data.get("found") is False:
            return "not found", {"found"}

    if selected:
        used_keys.update(str(key) for key, _ in selected)
        return " / ".join(
            (
                f"{_compact_value(value)} feeds checked"
                if source_name.lower() == "c2_trackers" and key == "sources_checked"
                else f"is C2 {_compact_value(value)}"
                if source_name.lower() == "c2_trackers" and key == "is_c2"
                else f"{_humanize(key)} {_compact_value(value)}"
            )
            for key, value in selected
        ), used_keys
    if not _is_empty(message):
        return _compact_value(message), {"message"}
    if source_data.get("found") is False:
        return "not found", {"found"}
    return "", used_keys


def _truncate_summary(value: str, limit: int = 60) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "\u2026"


def _make_row(
    source_name: str,
    source_data: Mapping[str, Any],
    source_class: str,
    score_breakdown: Mapping[str, Any] | None = None,
    ioc_type: str = "",
) -> dict[str, Any]:
    label = display_source_name(source_name)
    score = (
        score_breakdown.get("score_used")
        if isinstance(score_breakdown, Mapping)
        else _score_value(source_data)
    )
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        score = None
    score = float(score) if score is not None else None
    full_summary, summary_keys = _summary_parts(source_name, source_data, source_class)
    if isinstance(score_breakdown, Mapping):
        if score is not None and score > 0:
            weight = SOURCE_SCORING_MULTIPLIERS.get(source_name.lower())
            full_summary = (
                f"Score used {score:g}/100 (weight {weight:.2f})"
                if weight is not None
                else f"Score used {score:g}/100"
            )
        elif score_breakdown.get("flagged") is True:
            full_summary = "Flagged by the scoring source; no positive score used"
    detail_fields = [
        {"source_label": label, "key": _humanize(key), "value": _compact_value(value)}
        for key, value in source_data.items()
        if not _is_empty(value)
    ]
    extra_detail_fields = [
        field for field in detail_fields
        if field["key"] not in {"status", "score", "not applicable"}
    ]
    rank = {"flagged": 0, "other": 1, "error": 2, "clean": 3, "na": 4}.get(source_class, 1)
    normalized_score = score if score is not None else -1.0
    score_text = "-" if score is None else str(int(score)) if score.is_integer() else str(score)
    return {
        "source_name": source_name,
        "source_names": [source_name],
        "source_class": source_class,
        "display_name": label,
        "display_status": display_source_status(
            source_class,
            source_data.get("status"),
            score,
            source_name=source_name,
            source_data=source_data,
            ioc_type=ioc_type,
        ),
        "summary": _truncate_summary(full_summary),
        "summary_title": full_summary,
        "summary_keys": summary_keys,
        "detail_fields": detail_fields,
        "extra_detail_fields": extra_detail_fields,
        "has_details": any(
            field["key"].replace(" ", "_") not in summary_keys
            and field["key"].replace(" ", "_") not in {"status", "score", "not_applicable"}
            for field in detail_fields
        ),
        "score": score,
        "raw_status": _compact_value(source_data["status"]) if not _is_empty(source_data.get("status")) else "-",
        "raw_score": _compact_value(source_data["score"]) if not _is_empty(source_data.get("score")) else "-",
        "score_text": score_text,
        "score_width": max(0, min(100, score or 0)),
        "score_level": _score_level(score) if score is not None and score > 0 else "",
        "group_key": source_name,
        "score_breakdown": dict(score_breakdown) if isinstance(score_breakdown, Mapping) else None,
        "scored": source_name.lower() in SOURCE_SCORING_MULTIPLIERS,
        "weight": SOURCE_SCORING_MULTIPLIERS.get(source_name.lower()),
        "scoring_title": (
            (
                (
                    f"Score used: {score if score is not None else 'unavailable'}; "
                    f"weight {SOURCE_SCORING_MULTIPLIERS[source_name.lower()]:.2f}; "
                    f"contributed: {'yes' if score is not None and score > 0 else 'no'}"
                )
                if isinstance(score_breakdown, Mapping)
                else (
                    f"Counted in threat score, weight {SOURCE_SCORING_MULTIPLIERS[source_name.lower()]:.2f}; "
                    "contributes only when its score is greater than 0"
                )
            )
            if source_name.lower() in SOURCE_SCORING_MULTIPLIERS
            else ""
        ),
        "sort_key": (rank, -(normalized_score if rank in {0, 1} else 0), label.casefold()),
    }


def _merge_nrd_rows(
    first: dict[str, Any], second: dict[str, Any]
) -> dict[str, Any]:
    first_full = first["summary_title"]
    second_full = second["summary_title"]
    full_summary = " / ".join(part for part in (first_full, second_full) if part)
    scores = [row["score"] for row in (first, second) if row["score"] is not None]
    max_score = max(scores) if scores else None
    score_texts = [row["score_text"] for row in (first, second)]
    score_text = score_texts[0] if score_texts[0] == score_texts[1] else " / ".join(score_texts)
    detail_fields = first["detail_fields"] + second["detail_fields"]
    extra_detail_fields = first["extra_detail_fields"] + second["extra_detail_fields"]
    return {
        "source_name": "smet_nrd+hagezi_nrd",
        "source_names": first["source_names"] + second["source_names"],
        "source_class": first["source_class"],
        "display_name": "Smet NRD, HaGeZi NRD",
        "display_status": first["display_status"],
        "summary": _truncate_summary(full_summary),
        "summary_title": full_summary,
        "summary_keys": first["summary_keys"] | second["summary_keys"],
        "detail_fields": detail_fields,
        "extra_detail_fields": extra_detail_fields,
        "has_details": first["has_details"] or second["has_details"],
        "score": max_score,
        "raw_status": f"Smet NRD: {first['raw_status']} / HaGeZi NRD: {second['raw_status']}",
        "raw_score": f"Smet NRD: {first['raw_score']} / HaGeZi NRD: {second['raw_score']}",
        "score_text": score_text,
        "score_width": max(0, min(100, max_score or 0)),
        "score_level": _score_level(max_score) if max_score is not None and max_score > 0 else "",
        "group_key": "nrd",
        "scored": False,
        "weight": None,
        "scoring_title": "",
        "sort_key": first["sort_key"],
    }


def build_source_display_rows(
    sources: Mapping[str, Any],
    source_classes: Mapping[str, str] | None = None,
    score_breakdown: Mapping[str, Any] | None = None,
    ioc_type: str = "",
) -> list[dict[str, Any]]:
    """Build sorted display rows using supplied or shared report classes."""
    if not isinstance(sources, Mapping):
        return []
    if not isinstance(source_classes, Mapping):
        source_classes = {}
    if not isinstance(score_breakdown, Mapping):
        score_breakdown = {}

    rows_by_name: dict[str, dict[str, Any]] = {}
    for source_name, source_data in sources.items():
        if not isinstance(source_data, Mapping):
            continue
        source_class = source_classes.get(source_name)
        source_breakdown = score_breakdown.get(source_name)
        if source_class is None:
            source_class = classify_source(source_data, source_breakdown)
        if str(source_name).lower() == "sslblacklist" and ioc_type.lower() != "sha1":
            source_class = "na"
        rows_by_name[str(source_name)] = _make_row(
            str(source_name), source_data, source_class, source_breakdown, ioc_type
        )

    smet = rows_by_name.get("smet_nrd")
    hagezi = rows_by_name.get("hagezi_nrd")
    if smet is not None and hagezi is not None and smet["source_class"] == hagezi["source_class"]:
        merged = _merge_nrd_rows(smet, hagezi)
        rows = [
            row for key, row in rows_by_name.items()
            if key not in {"smet_nrd", "hagezi_nrd"}
        ]
        rows.append(merged)
    else:
        rows = list(rows_by_name.values())
    return sorted(rows, key=lambda row: row["sort_key"])
