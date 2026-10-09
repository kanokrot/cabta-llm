"""Shared report-source classification and counts.

Keep these rules aligned with the report template's source_summary logic.
The HTML template remains unchanged; PDF reporting uses this helper to mirror
its classes and counters.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SOURCE_CLASSES = ("flagged", "responded", "errors", "na")


def classify_source(source_data: Any) -> str:
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
    if source_data.get("listed") is True or status in {"found", "detected", "flagged"} or score >= 50:
        return "flagged"
    if status in {"not found", "clean", "ok"} or (score == 0 and status):
        return "clean"
    if status:
        return "other"
    return "na"


def count_source_classes(sources: Any) -> dict[str, int]:
    """Count flagged/responded/errors/N/A using report-template semantics."""
    counts = {key: 0 for key in SOURCE_CLASSES}
    if not isinstance(sources, Mapping):
        return counts

    for source_data in sources.values():
        if not isinstance(source_data, Mapping):
            continue
        source_class = classify_source(source_data)
        if source_class == "flagged":
            counts["flagged"] += 1
            counts["responded"] += 1
        elif source_class == "error":
            counts["errors"] += 1
        elif source_class == "na":
            counts["na"] += 1
        else:  # HTML classes "clean" and "other" both count as responded.
            counts["responded"] += 1
    return counts


def source_status_label(source_data: Any) -> str:
    """Return a clear text status label for a PDF source row."""
    source_class = classify_source(source_data)
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
