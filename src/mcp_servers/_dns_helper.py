"""Small, fail-soft DNS resolver shared by the MCP DNS tools.

The helper deliberately keeps the result object independent from the MCP
servers.  Callers decide how an empty answer or an exception maps to their
existing public response schema.
"""

from dataclasses import dataclass
import ipaddress
import os
import socket
import threading
import time
from typing import Optional

try:
    import dns.exception
    import dns.resolver
    import dns.reversename

    DNSPYTHON_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the fallback test
    dns = None
    DNSPYTHON_AVAILABLE = False


DEFAULT_FALLBACK_SERVERS = ("1.1.1.1", "8.8.8.8")
SYSTEM_UNHEALTHY_SECONDS = 60.0
DEFAULT_TIMEOUT_SECONDS = 3.0

_health_lock = threading.Lock()
_system_unhealthy_until = 0.0


@dataclass
class DNSQueryResult:
    """Normalized result for one DNS query."""

    answers: list[str]
    resolver: str
    status: str = "ok"
    error: Optional[str] = None


def dns_available() -> bool:
    """Return whether dnspython was importable when this module loaded."""

    return DNSPYTHON_AVAILABLE


def _timeout_seconds() -> float:
    raw = os.getenv("CABTA_DNS_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = DEFAULT_TIMEOUT_SECONDS
    return max(0.1, value)


def _fallback_enabled() -> bool:
    return os.getenv("CABTA_DNS_FALLBACK", "1").strip() != "0"


def fallback_servers() -> list[str]:
    raw = os.getenv("CABTA_DNS_FALLBACK_SERVERS", "")
    configured = [part.strip() for part in raw.split(",") if part.strip()]
    return configured or list(DEFAULT_FALLBACK_SERVERS)


def _system_is_unhealthy(now: Optional[float] = None) -> bool:
    current = time.monotonic() if now is None else now
    with _health_lock:
        return current < _system_unhealthy_until


def _mark_system_unhealthy() -> None:
    global _system_unhealthy_until
    with _health_lock:
        _system_unhealthy_until = time.monotonic() + SYSTEM_UNHEALTHY_SECONDS


def _mark_system_healthy() -> None:
    global _system_unhealthy_until
    with _health_lock:
        _system_unhealthy_until = 0.0


def reset_health_cache() -> None:
    """Reset in-process resolver health; useful for isolated callers/tests."""

    global _system_unhealthy_until
    with _health_lock:
        _system_unhealthy_until = 0.0


def _normalized_name(name: str) -> str:
    return str(name).strip().lower().rstrip(".")


def _address_from_ptr_name(name: str) -> Optional[str]:
    normalized = _normalized_name(name)
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        pass
    if normalized.endswith(".in-addr.arpa"):
        octets = normalized[: -len(".in-addr.arpa")].split(".")
        if len(octets) == 4 and all(part.isdigit() for part in octets):
            try:
                return str(ipaddress.ip_address(".".join(reversed(octets))))
            except ValueError:
                return None
    return None


def fallback_allowed(name: str, record_type: str = "A", address: Optional[str] = None) -> bool:
    """Apply the privacy guard before any public fallback is attempted."""

    normalized = _normalized_name(name)
    rtype = record_type.upper()
    if rtype == "PTR":
        candidate = address or _address_from_ptr_name(normalized)
        if candidate:
            try:
                parsed = ipaddress.ip_address(candidate)
                if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
                    return False
            except ValueError:
                pass
    if "." not in normalized:
        return False
    return not normalized.endswith((".local", ".internal", ".lan", ".corp", ".home"))


def _terminal_exception(exc: Exception) -> bool:
    if not DNSPYTHON_AVAILABLE:
        return False
    return isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer))


def _retryable_exception(exc: Exception) -> bool:
    if not DNSPYTHON_AVAILABLE:
        return False
    retryable = (
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        OSError,
        socket.timeout,
        TimeoutError,
        ConnectionError,
    )
    return isinstance(exc, retryable)


def _resolver(nameserver: Optional[str] = None):
    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver is not None:
        resolver.nameservers = [nameserver]
    timeout = _timeout_seconds()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _answer_strings(answer) -> list[str]:
    values = []
    for item in answer:
        value = getattr(item, "address", None)
        if value is None:
            value = str(item)
        values.append(str(value).rstrip("."))
    return values


def _query(resolver, name: str, record_type: str) -> list[str]:
    answer = resolver.resolve(name, record_type, lifetime=_timeout_seconds())
    return _answer_strings(answer)


def _result_for_exception(exc: Exception, resolver_name: str) -> DNSQueryResult:
    if DNSPYTHON_AVAILABLE and isinstance(exc, dns.resolver.NXDOMAIN):
        return DNSQueryResult([], resolver_name, status="nxdomain")
    if DNSPYTHON_AVAILABLE and isinstance(exc, dns.resolver.NoAnswer):
        return DNSQueryResult([], resolver_name, status="noanswer")
    return DNSQueryResult([], resolver_name, status="error", error=str(exc))


def resolve_record(
    name: str,
    record_type: str = "A",
    *,
    address: Optional[str] = None,
) -> DNSQueryResult:
    """Resolve one record, using the system resolver before public fallback."""

    if not DNSPYTHON_AVAILABLE:
        return DNSQueryResult([], "nslookup", status="unavailable")

    normalized = _normalized_name(name)
    rtype = record_type.upper()
    fallback_on = _fallback_enabled()
    system_name = "system"

    if not (fallback_on and _system_is_unhealthy()):
        try:
            values = _query(_resolver(), normalized, rtype)
            _mark_system_healthy()
            return DNSQueryResult(values, system_name)
        except Exception as exc:
            if _terminal_exception(exc):
                _mark_system_healthy()
                return _result_for_exception(exc, system_name)
            if not _retryable_exception(exc):
                return _result_for_exception(exc, system_name)
            _mark_system_unhealthy()
            if not fallback_on or not fallback_allowed(normalized, rtype, address):
                return _result_for_exception(exc, system_name)

    if fallback_on and fallback_allowed(normalized, rtype, address):
        last_error: Optional[Exception] = None
        servers = fallback_servers()
        for server in servers:
            try:
                values = _query(_resolver(server), normalized, rtype)
                _mark_system_healthy() if server == "system" else None
                return DNSQueryResult(values, f"fallback:{server}")
            except Exception as exc:
                if _terminal_exception(exc):
                    return _result_for_exception(exc, f"fallback:{server}")
                last_error = exc
                if not _retryable_exception(exc):
                    return _result_for_exception(exc, f"fallback:{server}")
        label = f"fallback:{servers[0]}" if servers else "system"
        return _result_for_exception(last_error or RuntimeError("no fallback resolver"), label)

    return DNSQueryResult([], system_name, status="error", error="fallback disabled or restricted")


def resolve_ptr(ip: str) -> DNSQueryResult:
    """Resolve an address through PTR while applying the private-network guard."""

    if not DNSPYTHON_AVAILABLE:
        return DNSQueryResult([], "nslookup", status="unavailable")
    try:
        ptr_name = dns.reversename.from_address(ip).to_text()
    except Exception as exc:
        return DNSQueryResult([], "system", status="error", error=str(exc))
    return resolve_record(ptr_name, "PTR", address=ip)


def combine_resolvers(labels: list[str]) -> str:
    """Choose one stable top-level resolver label for a multi-query result."""

    values = [label for label in labels if label]
    for label in values:
        if label.startswith("fallback:"):
            return label
    if "system" in values:
        return "system"
    if "nslookup" in values:
        return "nslookup"
    return "system"


def resolve_many(name: str, record_types: list[str], max_workers: int = 8):
    """Resolve record types concurrently and return results in input order."""

    from concurrent.futures import ThreadPoolExecutor

    if not record_types:
        return []
    workers = min(max_workers, len(record_types))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(resolve_record, name, rtype) for rtype in record_types]
        return [(rtype, future.result()) for rtype, future in zip(record_types, futures)]
