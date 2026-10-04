"""Read-only capability status checks for the email analysis pipeline."""

from __future__ import annotations

import copy
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
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
_CACHE: Optional[tuple[float, Dict[str, Any]]] = None


_CAPABILITIES = (
    ("spf_dkim_dmarc", "SPF / DKIM / DMARC", "email_authentication"),
    ("header_forensics", "Header forensics", "email_authentication"),
    ("url_analysis", "URL analysis", "threat_intelligence"),
    ("attachment_scanning", "Attachment scanning", "threat_intelligence"),
    ("brand_impersonation", "Brand impersonation", "threat_intelligence"),
    ("openphish_url", "OpenPhish URL check", "threat_intelligence"),
    ("malwarebazaar_hash", "MalwareBazaar hash", "threat_intelligence"),
    ("sender_domain_whois", "Sender domain WHOIS", "advanced_osint"),
    ("lookalike_domains", "Lookalike domains", "advanced_osint"),
    ("hudsonrock_breach", "HudsonRock breach check", "advanced_osint"),
    ("paste_monitoring", "Paste site monitoring", "advanced_osint"),
)


def _checked_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_probe_message() -> EmailMessage:
    message = EmailMessage()
    message["From"] = "probe@example.com"
    message["Received-SPF"] = "pass"
    message["Authentication-Results"] = "example.com; dkim=pass; dmarc=pass"
    message["Subject"] = "Capability probe"
    message.set_content("https://example.com/notice")
    return message


def _probe_local_capability(key: str) -> None:
    """Import and execute the local implementation used by EmailAnalyzer."""
    from src.analyzers.advanced_email_analyzer import AdvancedEmailAnalyzer
    from src.analyzers.email_forensics import EmailForensics
    from src.tools.email_analyzer import EmailAnalyzer

    message = _safe_probe_message()
    if key == "spf_dkim_dmarc":
        EmailAnalyzer._check_spf(None, message)
        EmailAnalyzer._check_dkim(None, message)
        EmailAnalyzer._check_dmarc(None, message)
    elif key == "header_forensics":
        AdvancedEmailAnalyzer.analyze_headers(message)
        EmailForensics.perform_full_forensics(message, "probe@example.com", "example.com")
    elif key == "brand_impersonation":
        AdvancedEmailAnalyzer.detect_brand_impersonation(
            "probe@example.com",
            "Capability probe",
            "https://example.com/notice",
            ["example.com"],
        )
    elif key == "lookalike_domains":
        AdvancedEmailAnalyzer.detect_lookalike_domains(["example.com"])
    else:
        raise ValueError(f"unsupported local capability: {key}")


def _load_config_for_probe() -> Dict[str, Any]:
    """Use the same config-loading shape as analysis.py without doing probes."""
    try:
        from src.utils.config import load_config

        return load_config()
    except Exception:
        return {}


def create_route_email_analyzer():
    """Create the analyzer exactly as the email background route does."""
    from src.tools.email_analyzer import EmailAnalyzer

    return EmailAnalyzer(_load_config_for_probe())


def inspect_email_pipeline_connections(analyzer=None) -> Dict[str, Any]:
    """Return connection facts that future email-analysis code can reuse."""
    if analyzer is None:
        analyzer = create_route_email_analyzer()

    ioc_investigator = getattr(analyzer, "ioc_investigator", None)
    file_analyzer = getattr(analyzer, "file_analyzer", None)
    return {
        "analyzer": analyzer,
        "ioc_investigator": ioc_investigator,
        "file_analyzer": file_analyzer,
        "ioc_connected": ioc_investigator is not None,
        "file_connected": file_analyzer is not None,
    }


def _entry(key: str, label: str, group: str, status: str, reason: str, checked_at: str) -> Dict[str, Any]:
    if status not in CAPABILITY_STATUSES:
        raise ValueError(f"invalid capability status: {status}")
    return {
        "key": key,
        "label": label,
        "group": group,
        "status": status,
        "checked_at": checked_at,
        "reason": reason,
    }


def _build_snapshot() -> Dict[str, Any]:
    checked_at = _checked_at()
    results: Dict[str, Dict[str, Any]] = {}

    for key in (
        "spf_dkim_dmarc",
        "header_forensics",
        "brand_impersonation",
        "lookalike_domains",
    ):
        try:
            _probe_local_capability(key)
            results[key] = {"status": "active", "reason": "local implementation is callable"}
        except Exception as exc:
            results[key] = {
                "status": "unreachable",
                "reason": f"local capability check failed: {type(exc).__name__}",
            }

    try:
        from src.analyzers.advanced_email_analyzer import AdvancedEmailAnalyzer

        AdvancedEmailAnalyzer.detect_link_text_mismatch("https://example.com/notice")
        results["url_analysis"] = {
            "status": "limited",
            "reason": "local checks only; IOC investigator is not connected by this endpoint",
        }
    except Exception as exc:
        results["url_analysis"] = {
            "status": "unreachable",
            "reason": f"local URL check failed: {type(exc).__name__}",
        }

    try:
        connection = inspect_email_pipeline_connections()
        analyzer = connection["analyzer"]
        if connection["file_connected"]:
            attachment = {"status": "active", "reason": "route-created analyzer has file_analyzer"}
        else:
            attachment = {
                "status": "not_connected",
                "reason": "route-created analyzer has no file_analyzer",
            }

        if connection["ioc_connected"]:
            sender_whois = {
                "status": "active",
                "reason": "route-created analyzer has ioc_investigator",
            }
            threat_intel = getattr(connection["ioc_investigator"], "threat_intel", None)
            api_keys = getattr(threat_intel, "api_keys", {}) or {}
            if api_keys.get("threatfox") or api_keys.get("abusech"):
                malware = {
                    "status": "active",
                    "reason": "MalwareBazaar path has a configured Abuse.ch key",
                }
            else:
                malware = {
                    "status": "needs_config",
                    "reason": "MalwareBazaar path has no configured Abuse.ch key",
                }
        else:
            sender_whois = {
                "status": "not_connected",
                "reason": "route-created analyzer has no ioc_investigator",
            }
            malware = {
                "status": "not_connected",
                "reason": "route-created analyzer has no ioc_investigator",
            }
        del analyzer
    except Exception as exc:
        attachment = {
            "status": "unreachable",
            "reason": f"route-created EmailAnalyzer check failed: {type(exc).__name__}",
        }
        sender_whois = dict(attachment)
        malware = dict(attachment)

    results.update(
        {
            "attachment_scanning": attachment,
            "sender_domain_whois": sender_whois,
            "malwarebazaar_hash": malware,
            "openphish_url": {
                "status": "not_connected",
                "reason": "not part of the email analysis pipeline",
            },
            "hudsonrock_breach": {
                "status": "not_connected",
                "reason": "not part of the email analysis pipeline",
            },
            "paste_monitoring": {
                "status": "not_connected",
                "reason": "not part of the email analysis pipeline",
            },
        }
    )

    capabilities = []
    for key, label, group in _CAPABILITIES:
        result = results[key]
        capabilities.append(_entry(
            key,
            label,
            group,
            result["status"],
            result["reason"],
            checked_at,
        ))
    return {"checked_at": checked_at, "capabilities": capabilities}


def clear_email_capability_cache() -> None:
    global _CACHE
    with _CACHE_LOCK:
        _CACHE = None


def get_email_capabilities(*, refresh: bool = False, include_reason: bool = False) -> Dict[str, Any]:
    """Return a cached capability snapshot, hiding reasons from non-admins."""
    global _CACHE
    now = time.monotonic()
    with _CACHE_LOCK:
        if refresh:
            _CACHE = None
        if _CACHE is None or now - _CACHE[0] >= _CACHE_TTL_SECONDS:
            _CACHE = (time.monotonic(), _build_snapshot())
        snapshot = copy.deepcopy(_CACHE[1])

    if not include_reason:
        for capability in snapshot["capabilities"]:
            capability.pop("reason", None)
    return snapshot
