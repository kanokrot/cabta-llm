"""Build safe, deterministic follow-up suggestions from structured IOC fields."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any


THREAT_HUNTER = "Threat Hunter"
ADMIN = "admin"
INCIDENT_RESPONDER = "Incident Responder"
MAX_SUGGESTIONS = 3

_HASH_PATTERNS = (
    re.compile(r"[0-9a-fA-F]{32}\Z"),
    re.compile(r"[0-9a-fA-F]{40}\Z"),
    re.compile(r"[0-9a-fA-F]{64}\Z"),
)
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SPECIAL_GLOBAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.0.0.0/24",
        "192.88.99.0/24",
        "2001::/23",
        "2002::/16",
    )
)
_PRIVATE_IOC_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_IOCs_BY_FIELD = {
    "ip": "ip",
    "ipv4": "ip",
    "ips": "ip",
    "ip_addresses": "ip",
    "domain": "domain",
    "domains": "domain",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hashes": "hash",
}
_IOCS_BY_TYPE = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip-address": "ip",
    "domain": "domain",
    "hostname": "domain",
    "hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
}


def _valid_domain(value: str) -> bool:
    if not value.isascii() or len(value) > 253 or value.endswith("."):
        return False
    labels = value.lower().split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        return False
    # A DNS name must have an alphabetic or valid punycode top-level label.
    tld = labels[-1]
    if tld.startswith("xn--"):
        try:
            decoded = tld.encode("ascii").decode("idna")
            if not decoded or decoded.encode("idna").decode("ascii").lower() != tld:
                return False
        except (UnicodeError, ValueError):
            return False
    elif len(tld) < 2 or not tld.isalpha():
        return False
    return True


def validate_ioc(value: Any, ioc_type: Any = None, *, allow_private: bool = False) -> str | None:
    """Return a canonical public IP, ASCII domain, or file hash, otherwise None."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    kind = _IOCS_BY_TYPE.get(ioc_type.lower()) if isinstance(ioc_type, str) else None

    if kind in (None, "ip"):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address is not None:
            special_global = any(
                address.version == network.version and address in network
                for network in _SPECIAL_GLOBAL_NETWORKS
            )
            allowed_private = allow_private and any(
                address.version == network.version and address in network
                for network in _PRIVATE_IOC_NETWORKS
            )
            return (
                str(address)
                if (
                    (address.is_global or allowed_private)
                    and not address.is_reserved
                    and not special_global
                    and kind != "domain"
                )
                else None
            )
        if kind == "ip":
            return None

    if kind in (None, "domain") and _valid_domain(value):
        return value.lower()
    if kind == "domain":
        return None

    if kind in (None, "hash") and any(pattern.fullmatch(value) for pattern in _HASH_PATTERNS):
        return value.lower()
    return None


def _string_values(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if isinstance(item, str):
                yield item


def _original_targets(findings: Sequence[Any]) -> set[str]:
    originals = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        params = finding.get("params")
        result = finding.get("result")
        for source in (params, result):
            if isinstance(source, Mapping):
                canonical = validate_ioc(source.get("ioc"), source.get("ioc_type"))
                if canonical:
                    originals.add(canonical)
    return originals


def _candidate_values(result: Mapping[str, Any]):
    for field, kind in _IOCs_BY_FIELD.items():
        for value in _string_values(result.get(field)):
            yield value, kind

    for container_name in ("iocs", "related_iocs", "ioc_overlaps"):
        container = result.get(container_name)
        if isinstance(container, Mapping):
            for field, kind in _IOCs_BY_FIELD.items():
                for value in _string_values(container.get(field)):
                    yield value, kind
        elif container_name in {"related_iocs", "ioc_overlaps"} and isinstance(container, Sequence) and not isinstance(
            container, (str, bytes, bytearray)
        ):
            for item in container:
                if not isinstance(item, Mapping):
                    continue
                kind = _IOCS_BY_TYPE.get(
                    item.get("ioc_type", item.get("type", "")).lower()
                    if isinstance(item.get("ioc_type", item.get("type", "")), str)
                    else ""
                )
                if kind:
                    yield item.get("ioc", item.get("value")), kind


def build_follow_up_suggestions(findings: Any, role: str) -> list[dict[str, str]]:
    """Return role-appropriate, fixed-text suggestions derived only from IOC fields."""
    if role == INCIDENT_RESPONDER:
        return []
    if role not in {THREAT_HUNTER, ADMIN}:
        return []

    findings_list = findings if isinstance(findings, (list, tuple)) else []
    suggestions = [{
        "kind": "prefill",
        "label": "ตรวจ IOC อื่น",
        "message": "Investigate another IOC: ",
    }]
    originals = _original_targets(findings_list)
    seen = set(originals)

    for finding in findings_list:
        if len(suggestions) >= MAX_SUGGESTIONS:
            break
        if not isinstance(finding, Mapping):
            continue
        result = finding.get("result")
        if not isinstance(result, Mapping):
            continue
        for raw_target, kind in _candidate_values(result):
            target = validate_ioc(raw_target, kind)
            if not target or target in seen:
                continue
            seen.add(target)
            message = f"Investigate related IOC: {target}"
            suggestions.append({"kind": "investigate", "label": message, "message": message})
            if len(suggestions) >= MAX_SUGGESTIONS:
                break

    return suggestions
