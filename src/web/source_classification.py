"""Shared source classification and counts for IOC result displays."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SOURCE_CLASSES = ("flagged", "responded", "errors", "na")


def classify_source(source_data: Any, score_breakdown: Any = None) -> str:
    """Return the report class used for one source row."""
    if not isinstance(source_data, Mapping):
        return "na"

    status = str(source_data.get("status", ""))
    try:
        score = int(source_data.get("score", 0) or 0)
    except (TypeError, ValueError):
        score = 0

    if source_data.get("not_applicable") or status in {"\u2796", "not_applicable"}:
        return "na"
    if (
        status in {"error", "\u26a0"}
        or "error" in source_data
        or source_data.get("feed_status") == "unavailable"
    ):
        return "error"
    if isinstance(score_breakdown, Mapping):
        score_used = score_breakdown.get("score_used")
        if score_breakdown.get("flagged") is True:
            return "flagged"
        if (
            isinstance(score_used, (int, float))
            and not isinstance(score_used, bool)
        ):
            return "flagged" if score_used > 0 else "clean"
        return "other"
    if source_data.get("listed") is True or status in {"found", "detected", "flagged"} or score >= 50:
        return "flagged"
    if status in {"not found", "clean", "ok"} or (score == 0 and status):
        return "clean"
    if status:
        return "other"
    return "na"


def count_source_classes(
    sources: Any, score_breakdown: Mapping[str, Any] | None = None
) -> dict[str, int]:
    """Count source classes plus scored/context split and attempted total."""
    counts = {
        **{key: 0 for key in SOURCE_CLASSES},
        "scored_flagged": 0,
        "context_flagged": 0,
        "attempted": 0,
    }
    classes = classify_sources(sources, score_breakdown)
    if not isinstance(score_breakdown, Mapping):
        score_breakdown = {}

    for source_name, source_class in classes.items():
        if source_class == "flagged":
            counts["flagged"] += 1
            counts["responded"] += 1
            breakdown = score_breakdown.get(source_name)
            if isinstance(breakdown, Mapping) and breakdown.get("scored") is True:
                counts["scored_flagged"] += 1
            else:
                counts["context_flagged"] += 1
        elif source_class == "error":
            counts["errors"] += 1
        elif source_class == "na":
            counts["na"] += 1
        else:  # HTML classes "clean" and "other" both count as responded.
            counts["responded"] += 1
    counts["attempted"] = counts["responded"] + counts["errors"]
    return counts


def classify_sources(
    sources: Any, score_breakdown: Mapping[str, Any] | None = None
) -> dict[str, str]:
    """Return the shared display class for each source mapping."""
    if not isinstance(sources, Mapping):
        return {}
    if not isinstance(score_breakdown, Mapping):
        score_breakdown = {}

    return {
        str(source_name): classify_source(
            source_data, score_breakdown.get(source_name)
        )
        for source_name, source_data in sources.items()
        if isinstance(source_data, Mapping)
    }


def build_report_source_summary(result: Any) -> dict[str, Any]:
    """Build the shared source-count and top-source summary for report views."""
    if not isinstance(result, dict):
        result = {}
    sources = result.get("sources", {})
    score_breakdown = result.get("score_breakdown", {})
    counts = count_source_classes(sources, score_breakdown)
    classes = classify_sources(sources, score_breakdown)

    top_name = "N/A"
    top_score = -1
    has_breakdown = isinstance(score_breakdown, dict) and bool(score_breakdown)
    if isinstance(sources, dict):
        for source_name, source_data in sources.items():
            if not isinstance(source_data, dict):
                continue
            breakdown = (
                score_breakdown.get(source_name)
                if isinstance(score_breakdown, dict)
                else None
            )
            raw_score = (
                breakdown.get("score_used")
                if isinstance(breakdown, dict)
                else source_data.get("score", 0)
            )
            try:
                score = int(raw_score or 0)
            except (TypeError, ValueError):
                score = 0
            if isinstance(breakdown, dict):
                is_top_candidate = score > 0
            else:
                is_top_candidate = (
                    not has_breakdown
                    and classes.get(source_name) not in {"na", "error"}
                )
            if is_top_candidate and score > top_score:
                top_score = score
                top_name = str(source_name).title()

    return {
        **counts,
        "classes": classes,
        "top_name": top_name,
        "top_score": top_score,
    }


def source_status_label(source_data: Any, score_breakdown: Any = None) -> str:
    """Return a clear text status label for a PDF source row."""
    source_class = classify_source(source_data, score_breakdown)
    if source_class == "flagged":
        return "FLAGGED"
    if source_class == "error":
        return "ERROR"
    if source_class == "na":
        return "N/A"
    if source_class == "clean":
        return "CLEAN"

    data = source_data if isinstance(source_data, Mapping) else {}
    status = str(data.get("status", "") or "").strip().lower()
    score = data.get("score")
    try:
        numeric_score = float(score) if score is not None else None
    except (TypeError, ValueError):
        numeric_score = None

    if status in {"clean", "ok", "not found", "\u2717"}:
        return "CLEAN"
    if status in {"\u23f3", "pending"}:
        return "PENDING"
    if status in {"\u2713", "found", "detected", "flagged"}:
        return "REPORTED" if numeric_score is not None and numeric_score > 0 else "RESPONDED"
    return "RESPONDED"
