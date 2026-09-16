"""Response serializers for role-scoped, non-raw analysis data."""

import json
from typing import Any, Dict


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


def serialize_analysis_job(job: Dict[str, Any]) -> Dict[str, Any]:
    """Return the common SOC/Team Lead analysis representation.

    The allowlisted fields deliberately exclude raw ``params`` and
    ``result`` payloads, which can contain uploaded source paths, source
    details, or provider-specific response data.
    """
    params = _as_dict(job.get("params"))
    result = _as_dict(job.get("result"))
    output = {
        "id": job.get("id"),
        "analysis_type": job.get("analysis_type"),
        "status": job.get("status"),
        "progress": job.get("progress", 0),
        "current_step": job.get("current_step", ""),
        "verdict": job.get("verdict") or result.get("verdict") or "UNKNOWN",
        "score": job.get("score"),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "ioc": params.get("value"),
        "ioc_type": params.get("ioc_type"),
        "filename": params.get("filename"),
        "sha256": params.get("sha256"),
        "size": params.get("size"),
        "summary": result.get("summary"),
        "confidence": result.get("confidence"),
    }
    return output
