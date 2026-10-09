"""Per-source explanation of the existing IOC scoring inputs.

This module reports how ``IntelligentScoring.calculate_ioc_score`` treated
each configured IOC scoring source. It does not calculate or change the final
threat score.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .intelligent_scoring import (
    IntelligentScoring,
    SOURCE_SCORING_MULTIPLIERS,
)


_FLAGGED_STATUSES = {"✓", "✓ FLAGGED", "FLAGGED", "flagged"}


def build_ioc_score_breakdown(intel_results: Any) -> dict[str, dict[str, Any]]:
    """Describe each scoring source's exact contribution eligibility.

    ``flagged`` mirrors the status-based source count used by the scorer,
    ``score_used`` is the positive score included in the weighted average (0
    for a successful clean response, ``None`` when unavailable), ``weight``
    is the configured source multiplier, and ``scored`` means the source
    contributed a positive weighted term to this result.
    """
    sources = intel_results.get("sources", {}) if isinstance(intel_results, Mapping) else {}
    if not isinstance(sources, Mapping):
        return {}

    breakdown: dict[str, dict[str, Any]] = {}
    for source_name, source_data in sources.items():
        normalized_name = str(source_name).lower()
        weight = SOURCE_SCORING_MULTIPLIERS.get(normalized_name)
        if weight is None:
            continue

        is_error = (
            not isinstance(source_data, dict)
            or IntelligentScoring._is_source_error(source_data)
        )
        status = str(source_data.get("status", "")) if isinstance(source_data, dict) else ""
        raw_score = (
            IntelligentScoring._get_source_score(source_data)
            if not is_error
            else None
        )
        score_used = None if raw_score is None else max(0, int(raw_score))
        scored = score_used is not None and score_used > 0

        breakdown[str(source_name)] = {
            "flagged": not is_error and status in _FLAGGED_STATUSES,
            "score_used": score_used,
            "weight": weight,
            "scored": scored,
        }

    return breakdown
