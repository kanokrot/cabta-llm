"""Read-only capability status checks for the file analysis pipeline."""

from __future__ import annotations

import copy
import importlib
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional


CAPABILITY_STATUSES = {
    "active",
    "limited",
    "not_connected",
    "needs_config",
    "unreachable",
}

_CACHE_TTL_SECONDS = 300.0
_CACHE_LOCK = threading.Lock()
_CACHE: Optional[tuple[float, Optional[int], Dict[str, Any]]] = None

_GROUP_LABELS = {
    "core": "Core analysis",
    "detection": "Detection",
    "format": "Format analyzers",
    "threat_intelligence": "Threat intelligence",
}

_CAPABILITIES = (
    ("static_analysis", "Static analysis", "core"),
    ("string_extraction", "String extraction", "core"),
    ("yara_rules", "YARA rules", "detection"),
    ("ioc_extraction", "IOC extraction", "detection"),
    ("macro_analysis", "Macro analysis", "format", "OLEVBA"),
    ("pe_analysis", "PE analysis", "format", "PEFILE"),
    ("mitre_mapping", "MITRE ATT&CK mapping", "threat_intelligence"),
    (
        "hash_reputation",
        "Hash reputation",
        "threat_intelligence",
        "MALWAREBAZAAR",
    ),
    ("epss_score", "EPSS score", "threat_intelligence"),
    (
        "malpedia_family",
        "Malpedia family",
        "threat_intelligence",
        None,
        True,
    ),
)


def _checked_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entry(
    key: str,
    label: str,
    group: str,
    status: str,
    reason: str,
    *,
    provider: Optional[str] = None,
    beta: bool = False,
) -> Dict[str, Any]:
    if status not in CAPABILITY_STATUSES:
        raise ValueError(f"invalid capability status: {status}")

    entry: Dict[str, Any] = {
        "key": key,
        "label": label,
        "group": group,
        "group_label": _GROUP_LABELS[group],
        "status": status,
        "reason": reason,
    }
    if beta:
        entry["beta"] = True
    if provider:
        entry["provider"] = provider
    return entry


def _available_import(module_name: str) -> tuple[bool, str]:
    try:
        importlib.import_module(module_name)
        return True, f"{module_name} import is available"
    except Exception as exc:
        return False, f"{module_name} import failed: {type(exc).__name__}"


def _probe_yara_rules() -> tuple[str, str]:
    """Check the same built-in YARA rule loading path without scanning a file."""
    available, _ = _available_import("yara")
    if not available:
        return "needs_config", "yara is not installed"

    try:
        scanner_module = importlib.import_module("src.utils.yara_scanner")
        scanner = scanner_module.YaraScanner()
        if scanner.rules is None:
            return "needs_config", "yara rules could not be loaded"
        return "active", "yara-python imported and built-in rules loaded"
    except Exception as exc:
        return "needs_config", f"yara rules could not be loaded: {type(exc).__name__}"


def _local_analyzer_status(analyzer: Any, attribute: str, method: str, name: str):
    if analyzer is None:
        return "not_connected", f"route-wired MalwareAnalyzer has no {name}"
    component = analyzer if not attribute else getattr(analyzer, attribute, None)
    if callable(getattr(component, method, None)):
        return "active", f"route-wired MalwareAnalyzer exposes {name}"
    return "needs_config", f"route-wired MalwareAnalyzer has no callable {name}"


def _hash_reputation_status(analyzer: Any) -> tuple[str, str]:
    if analyzer is None:
        return "not_connected", "route-wired MalwareAnalyzer is unavailable"

    threat_intel = getattr(analyzer, "threat_intel", None)
    checker = getattr(threat_intel, "check_malwarebazaar", None)
    if not callable(checker):
        return "not_connected", "MalwareAnalyzer has no MalwareBazaar client"

    api_keys = getattr(threat_intel, "api_keys", {}) or {}
    try:
        from src.utils.api_key_validator import get_valid_key

        configured = any(
            get_valid_key(api_keys, key) for key in ("malwarebazaar", "threatfox", "abusech")
        )
    except Exception:
        configured = any(api_keys.get(key) for key in ("malwarebazaar", "threatfox", "abusech"))

    if configured:
        return "active", "MalwareBazaar client and Abuse.ch API key are configured"
    return "needs_config", "MalwareBazaar client exists but Abuse.ch API key is not configured"


def _build_snapshot(analyzer: Any = None) -> Dict[str, Any]:
    checked_at = _checked_at()
    results: Dict[str, Dict[str, Any]] = {}

    status, reason = _local_analyzer_status(analyzer, "", "analyze", "static analysis")
    results["static_analysis"] = {"status": status, "reason": reason}

    if analyzer is None:
        results["string_extraction"] = {
            "status": "not_connected",
            "reason": "route-wired MalwareAnalyzer is unavailable",
        }
        results["ioc_extraction"] = {
            "status": "not_connected",
            "reason": "route-wired MalwareAnalyzer is unavailable",
        }
    else:
        extractor = getattr(analyzer, "string_extractor", None)
        if callable(getattr(extractor, "extract_strings", None)):
            results["string_extraction"] = {
                "status": "active",
                "reason": "MalwareAnalyzer has a callable StringExtractor",
            }
        else:
            results["string_extraction"] = {
                "status": "needs_config",
                "reason": "MalwareAnalyzer has no callable StringExtractor",
            }
        if callable(getattr(extractor, "extract_iocs_from_strings", None)):
            results["ioc_extraction"] = {
                "status": "active",
                "reason": "MalwareAnalyzer has callable IOC extraction from strings",
            }
        else:
            results["ioc_extraction"] = {
                "status": "needs_config",
                "reason": "MalwareAnalyzer has no callable IOC extraction path",
            }

    yara_status, yara_reason = _probe_yara_rules()
    results["yara_rules"] = {"status": yara_status, "reason": yara_reason}

    for key, module_name, package in (
        ("macro_analysis", "oletools.olevba", "oletools"),
        ("pe_analysis", "pefile", "pefile"),
    ):
        available, _ = _available_import(module_name)
        results[key] = {
            "status": "active" if available else "needs_config",
            "reason": f"{package} import is available" if available else f"{package} is not installed",
        }

    if analyzer is None:
        results["mitre_mapping"] = {
            "status": "not_connected",
            "reason": "route-wired MalwareAnalyzer is unavailable",
        }
    elif callable(getattr(analyzer, "_generate_mitre_mapping", None)):
        results["mitre_mapping"] = {
            "status": "active",
            "reason": "MalwareAnalyzer exposes local MITRE mapping",
        }
    else:
        results["mitre_mapping"] = {
            "status": "needs_config",
            "reason": "MalwareAnalyzer has no callable MITRE mapping path",
        }

    hash_status, hash_reason = _hash_reputation_status(analyzer)
    results["hash_reputation"] = {"status": hash_status, "reason": hash_reason}
    results["epss_score"] = {
        "status": "not_connected",
        "reason": "no non-network EPSS client is wired into file analysis",
    }
    results["malpedia_family"] = {
        "status": "not_connected",
        "reason": "no non-network Malpedia client is wired into file analysis",
    }

    capabilities = []
    for definition in _CAPABILITIES:
        key, label, group = definition[:3]
        provider = definition[3] if len(definition) > 3 else None
        beta = bool(definition[4]) if len(definition) > 4 else False
        result = results[key]
        capabilities.append(
            _entry(
                key,
                label,
                group,
                result["status"],
                result["reason"],
                provider=provider,
                beta=beta,
            )
        )
    return {"checked_at": checked_at, "capabilities": capabilities}


def clear_file_capability_cache() -> None:
    global _CACHE
    with _CACHE_LOCK:
        _CACHE = None


def get_file_capabilities(
    *,
    analyzer: Any = None,
    refresh: bool = False,
    include_reason: bool = False,
) -> Dict[str, Any]:
    """Return a cached file-capability snapshot, hiding reasons from non-admins."""
    global _CACHE
    now = time.monotonic()
    analyzer_marker = id(analyzer) if analyzer is not None else None
    with _CACHE_LOCK:
        if refresh:
            _CACHE = None
        if (
            _CACHE is None
            or now - _CACHE[0] >= _CACHE_TTL_SECONDS
            or _CACHE[1] != analyzer_marker
        ):
            _CACHE = (time.monotonic(), analyzer_marker, _build_snapshot(analyzer))
        snapshot = copy.deepcopy(_CACHE[2])

    if not include_reason:
        for capability in snapshot["capabilities"]:
            capability.pop("reason", None)
    return snapshot
