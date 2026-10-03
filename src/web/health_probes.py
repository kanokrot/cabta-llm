"""Read-only dependency probes for the detailed administrator health check."""

from __future__ import annotations

import asyncio
import copy
import os
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Awaitable, Callable

import aiohttp

from ..utils.api_key_validator import get_valid_key


HEALTH_VERSION = "2.0.0"
CACHE_TTL_SECONDS = 30.0
MIN_REFRESH_INTERVAL_SECONDS = 5.0
PROBE_TIMEOUT_SECONDS = 4.0
_START_TIME = datetime.now(timezone.utc)

CHECK_TIERS = {
    "llm": "important",
    "sqlite": "critical",
    "chromadb": "important",
    "mcp": "important",
    "threat_intel": "optional",
    "background_work": "informational",
    "disk": "optional",
}

_DB_NAMES = (
    "auth",
    "analysis_jobs",
    "agent",
    "agent_memory",
    "cases",
    "ioc_cache",
    "tickets",
)

_DB_TIERS = {
    "auth": "critical",
    "analysis_jobs": "critical",
    "agent": "important",
    "agent_memory": "important",
    "cases": "important",
    "tickets": "important",
    "ioc_cache": "optional",
}

_cached_result: dict[str, Any] | None = None
_cached_at: float | None = None
_last_probe_at: float | None = None
_cache_lock = asyncio.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_error(exc: BaseException) -> str:
    """Return only the exception name, except for a small safe-message allowlist."""
    name = type(exc).__name__
    message = str(exc).strip()
    if message.lower() in {
        "timed out",
        "database is locked",
        "unable to open database file",
    }:
        return f"{name}: {message}"
    return name


def _status(status: str, summary: str, **values: Any) -> dict[str, Any]:
    result = {"status": status, "summary": summary}
    result.update(values)
    return result


def _timed_result(func: Callable[..., dict[str, Any]], *args: Any) -> dict[str, Any]:
    started = time.perf_counter()
    result = func(*args)
    result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


def _timed_value(func: Callable[..., Any], *args: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    value = func(*args)
    return value, round((time.perf_counter() - started) * 1000, 1)


def aggregate_status(checks: dict[str, dict[str, Any]]) -> tuple[str, dict[str, int]]:
    """Aggregate statuses without treating non-probed states as unhealthy."""
    summary = {"healthy": 0, "degraded": 0, "unhealthy": 0}
    for check in checks.values():
        status = check.get("status")
        if status in summary:
            summary[status] += 1

    critical_unhealthy = any(
        CHECK_TIERS.get(name) == "critical"
        and check.get("status") == "unhealthy"
        for name, check in checks.items()
    )
    has_actionable_problem = any(
        check.get("status") in {"unhealthy", "degraded"}
        for name, check in checks.items()
        if CHECK_TIERS.get(name) != "informational"
    )
    if critical_unhealthy:
        return "unhealthy", summary
    if has_actionable_problem:
        return "degraded", summary
    return "healthy", summary


def _auth_db_path() -> Path:
    from .auth import AUTH_DB_ENV

    return Path(os.getenv(AUTH_DB_ENV, "src/db/auth.db"))


def _db_paths() -> dict[str, Path]:
    from ..agent import agent_store, memory
    from ..cache import ioc_cache
    from . import analysis_manager, case_store
    from ..integrations import ticketing

    return {
        "auth": _auth_db_path(),
        "analysis_jobs": analysis_manager._DEFAULT_DB,
        "agent": agent_store._DEFAULT_DB,
        "agent_memory": memory._DEFAULT_DB,
        "cases": case_store._DEFAULT_DB,
        "ioc_cache": ioc_cache._DEFAULT_DB,
        "tickets": Path(ticketing._get_db_path()),
    }


def _sqlite_uri(path: Path) -> str:
    resolved = path.expanduser().resolve()
    return resolved.as_uri() + "?mode=ro"


def _probe_one_database(name: str, path: Path) -> dict[str, Any]:
    started = time.perf_counter()
    tier = _DB_TIERS[name]
    if not path.exists():
        return _status(
            "not_initialized",
            "Database file is not initialized",
            name=name,
            tier=tier,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
        )

    connection = None
    try:
        connection = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=2)
        connection.execute("SELECT 1").fetchone()
        result = _status(
            "healthy",
            "Read-only database probe succeeded",
            name=name,
            tier=tier,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
        )
        if name == "analysis_jobs":
            rows = connection.execute(
                "SELECT status, COUNT(*) FROM analysis_jobs GROUP BY status"
            ).fetchall()
            result["_analysis_counts"] = {
                str(status): int(count) for status, count in rows
            }
        return result
    except Exception as exc:
        return _status(
            "unhealthy" if tier == "critical" else "degraded",
            "Read-only database probe failed",
            name=name,
            tier=tier,
            error=_safe_error(exc),
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
        )
    finally:
        if connection is not None:
            connection.close()


def _probe_sqlite_sync() -> dict[str, Any]:
    paths = _db_paths()
    databases = {name: _probe_one_database(name, paths[name]) for name in _DB_NAMES}
    analysis_counts = databases["analysis_jobs"].pop("_analysis_counts", {})

    not_initialized = [
        name for name, item in databases.items() if item["status"] == "not_initialized"
    ]
    failures = [
        name
        for name, item in databases.items()
        if item["status"] in {"degraded", "unhealthy"}
    ]
    critical_not_initialized = any(
        name in not_initialized and _DB_TIERS[name] == "critical"
        for name in _DB_NAMES
    )
    critical_failed = any(
        name in failures and _DB_TIERS[name] == "critical" for name in _DB_NAMES
    )
    if critical_not_initialized or critical_failed:
        overall = "unhealthy"
    elif failures:
        overall = "degraded"
    else:
        overall = "healthy"
    open_count = sum(item["status"] == "healthy" for item in databases.values())
    summary = f"{open_count} of {len(_DB_NAMES)} databases open"
    if not_initialized:
        summary += (
            f", {len(not_initialized)} not initialized "
            f"({', '.join(not_initialized)})"
        )
    if failures:
        summary += f", failed: {', '.join(failures)}"
    return _status(
        overall,
        summary,
        databases=databases,
        _analysis_counts=analysis_counts,
    )


async def _probe_sqlite() -> dict[str, Any]:
    return await asyncio.to_thread(_timed_result, _probe_sqlite_sync)


def _llm_analyzer_from_app(app: Any) -> Any:
    analyzer = getattr(app.state, "llm_analyzer", None)
    config = getattr(app.state, "config", None) or {}
    llm = config.get("llm", {}) if isinstance(config, dict) else {}
    if analyzer is not None:
        return analyzer
    return SimpleNamespace(
        provider=llm.get("provider", "ollama"),
        ollama_endpoint=llm.get("ollama_endpoint", "http://localhost:11434"),
        vllm_base_url=llm.get("vllm_base_url"),
        vllm_api_key=llm.get("vllm_api_key"),
        anthropic_key=(config.get("api_keys", {}) or {}).get("anthropic", ""),
    )


async def _probe_ollama(analyzer: Any) -> dict[str, Any]:
    from .routes.config_api import _check_ollama_health

    endpoint = getattr(analyzer, "ollama_endpoint", None) or "http://localhost:11434"
    result = await _check_ollama_health(endpoint)
    running = bool(result.get("ollama_running"))
    model_available = bool(result.get("model_available"))
    if not running:
        status = "unhealthy"
        summary = "Ollama is unavailable"
    elif not model_available:
        status = "degraded"
        summary = "Ollama is running but the configured model is unavailable"
    else:
        status = "healthy"
        summary = "Ollama is running and the configured model is available"
    return _status(
        status,
        summary,
        running=running,
        model_available=model_available,
        configured_model=str(result.get("configured_model") or ""),
    )


async def _probe_vllm(analyzer: Any) -> dict[str, Any]:
    base_url = str(getattr(analyzer, "vllm_base_url", "") or "").rstrip("/")
    if not base_url:
        return _status("not_configured", "vLLM base URL is not configured")

    headers = {"content-type": "application/json"}
    api_key = getattr(analyzer, "vllm_api_key", None)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    started = time.perf_counter()
    try:
        timeout = aiohttp.ClientTimeout(total=3, connect=2)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"{base_url}/v1/models", headers=headers) as response:
                latency_ms = round((time.perf_counter() - started) * 1000, 1)
                if response.status == 200:
                    return _status(
                        "healthy",
                        "vLLM models endpoint responded",
                        latency_ms=latency_ms,
                    )
                if response.status in {401, 403}:
                    return _status(
                        "degraded",
                        "vLLM models endpoint requires authorization",
                        latency_ms=latency_ms,
                    )
                return _status(
                    "unhealthy" if response.status >= 500 else "degraded",
                    f"vLLM models endpoint returned HTTP {response.status}",
                    latency_ms=latency_ms,
                )
    except Exception as exc:
        return _status("unhealthy", "vLLM probe failed", error=_safe_error(exc))


async def _probe_llm(app: Any) -> dict[str, Any]:
    analyzer = _llm_analyzer_from_app(app)
    provider = str(getattr(analyzer, "provider", "ollama") or "ollama").lower()
    ollama, vllm = await asyncio.gather(
        _probe_ollama(analyzer),
        _probe_vllm(analyzer),
        return_exceptions=True,
    )
    if isinstance(ollama, BaseException):
        ollama = _status("unhealthy", "Ollama probe failed", error=_safe_error(ollama))
    if isinstance(vllm, BaseException):
        vllm = _status("unhealthy", "vLLM probe failed", error=_safe_error(vllm))

    if provider == "ollama":
        active = ollama
    elif provider == "vllm":
        active = vllm
    elif provider == "anthropic":
        active = (
            _status("healthy", "Anthropic is configured")
            if getattr(analyzer, "anthropic_key", None)
            else _status("not_configured", "Anthropic API key is not configured")
        )
    else:
        active = _status("unknown", "Active LLM provider is unknown")

    return _status(
        active["status"],
        f"Active provider: {provider}",
        active_provider=provider,
        ollama=ollama,
        vllm=vllm,
    )


def _find_rag_instance(app: Any) -> Any:
    candidates = [
        getattr(app.state, "rag_knowledge_base", None),
        getattr(app.state, "ioc_investigator", None),
        getattr(app.state, "malware_analyzer", None),
        getattr(app.state, "email_analyzer", None),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        if callable(getattr(candidate, "status", None)):
            return candidate
        rag = getattr(candidate, "rag_kb", None)
        if rag is not None and callable(getattr(rag, "status", None)):
            return rag
    return None


async def _probe_chromadb(app: Any) -> dict[str, Any]:
    rag = _find_rag_instance(app)
    if rag is None:
        return _status("not_loaded", "No RAG knowledge base instance is loaded")
    try:
        result, latency_ms = await asyncio.to_thread(_timed_value, rag.status)
        return _status(
            "healthy",
            "ChromaDB knowledge base status is available",
            collection=result.get("collection"),
            document_count=result.get("document_count"),
            latency_ms=latency_ms,
        )
    except Exception as exc:
        return _status("unhealthy", "ChromaDB status probe failed", error=_safe_error(exc))


async def _probe_mcp(app: Any) -> dict[str, Any]:
    client = getattr(app.state, "mcp_client", None)
    if client is None:
        return _status("not_initialized", "MCP client is not initialized")
    try:
        runtime, latency_ms = await asyncio.to_thread(
            _timed_value, client.get_connection_status
        )
        runtime = runtime if isinstance(runtime, dict) else {}
        total = len(runtime)
        connected = sum(1 for item in runtime.values() if item.get("connected"))
        servers = {
            name: {
                "connected": bool(item.get("connected")),
                "tool_count": int(item.get("tool_count", 0) or 0),
            }
            for name, item in runtime.items()
            if isinstance(item, dict)
        }
        if total == 0:
            status = "not_initialized"
            summary = "No MCP servers are registered"
        elif connected == total:
            status = "healthy"
            summary = "All registered MCP servers are connected"
        else:
            status = "degraded"
            summary = "Some registered MCP servers are disconnected"
        return _status(
            status,
            summary,
            connected=connected,
            total=total,
            servers=servers,
            latency_ms=latency_ms,
        )
    except Exception as exc:
        return _status("unhealthy", "MCP status probe failed", error=_safe_error(exc))


def _find_misp_feed(app: Any) -> Any:
    candidates = [
        getattr(app.state, "misp_feed", None),
        getattr(app.state, "ioc_investigator", None),
        getattr(app.state, "malware_analyzer", None),
        getattr(app.state, "email_analyzer", None),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        if callable(getattr(candidate, "_feed_status", None)):
            return candidate
        for attr in ("threat_intel", "misp_feed"):
            nested = getattr(candidate, attr, None)
            if nested is not None and callable(getattr(nested, "_feed_status", None)):
                return nested
    return None


def _probe_threat_intel_sync(app: Any) -> dict[str, Any]:
    config = getattr(app.state, "config", None) or {}
    api_keys = config.get("api_keys", {}) if isinstance(config, dict) else {}
    if not isinstance(api_keys, dict):
        api_keys = {}
    source_keys = {
        "virustotal": bool(get_valid_key(api_keys, "virustotal")),
        "abuseipdb": bool(get_valid_key(api_keys, "abuseipdb")),
        "shodan": bool(get_valid_key(api_keys, "shodan")),
        "alienvault": bool(get_valid_key(api_keys, "alienvault")),
        "threatfox": bool(get_valid_key(api_keys, "threatfox")),
        "abusech": bool(get_valid_key(api_keys, "abusech")),
    }
    misp = _find_misp_feed(app)
    misp_status = None
    if misp is not None:
        try:
            misp_status = str(misp._feed_status())
        except Exception:
            misp_status = "unknown"
    if misp_status == "fresh":
        overall = "healthy"
    elif misp_status in {"stale", "unknown"}:
        overall = "degraded"
    elif any(source_keys.values()):
        overall = "healthy"
    else:
        overall = "not_configured"
    return _status(
        overall,
        "API-key configuration was checked without external requests",
        sources=source_keys,
        misp={"feed_status": misp_status} if misp_status is not None else {"status": "not_loaded"},
    )


async def _probe_threat_intel(app: Any) -> dict[str, Any]:
    return await asyncio.to_thread(_timed_result, _probe_threat_intel_sync, app)


async def _probe_background(
    analysis_counts: dict[str, int],
    agent_store: Any,
) -> dict[str, Any]:
    started = time.perf_counter()
    result: dict[str, Any] = {
        "status": "healthy",
        "summary": "Background work status is informational",
        "jobs": {
            "queued": int(analysis_counts.get("queued", 0)),
            "running": int(analysis_counts.get("running", 0)),
            "failed": int(analysis_counts.get("failed", 0)),
        },
    }
    if agent_store is None:
        result["agent_sessions"] = {"status": "not_initialized"}
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
        return result
    try:
        result["agent_sessions"], result["latency_ms"] = await asyncio.to_thread(
            _timed_value, agent_store.get_agent_stats
        )
    except Exception as exc:
        result["agent_sessions"] = {"status": "unknown", "error": _safe_error(exc)}
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


def _probe_disk_sync() -> dict[str, Any]:
    try:
        auth_path = _auth_db_path()
        directory = auth_path.parent
        while not directory.exists() and directory.parent != directory:
            directory = directory.parent
        usage = shutil.disk_usage(str(directory))
        free_percent = (usage.free / usage.total * 100) if usage.total else 0.0
        degraded = free_percent < 10.0 or usage.free < 5 * 1024**3
        return _status(
            "degraded" if degraded else "healthy",
            "Disk space is below the configured safety threshold" if degraded else "Disk space is available",
            free_gb=round(usage.free / 1024**3, 2),
            free_percent=round(free_percent, 2),
        )
    except Exception as exc:
        return _status("unknown", "Disk usage probe unavailable", error=_safe_error(exc))


async def _probe_disk() -> dict[str, Any]:
    return await asyncio.to_thread(_timed_result, _probe_disk_sync)


async def _run_probe(name: str, probe: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(probe, timeout=PROBE_TIMEOUT_SECONDS)
        result.setdefault("latency_ms", round((time.perf_counter() - started) * 1000, 1))
        result["tier"] = CHECK_TIERS[name]
        return result
    except asyncio.TimeoutError:
        return _status(
            "unhealthy",
            f"{name} probe timed out",
            tier=CHECK_TIERS[name],
            error="TimeoutError",
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
        )
    except Exception as exc:
        return _status(
            "unhealthy",
            f"{name} probe failed",
            tier=CHECK_TIERS[name],
            error=_safe_error(exc),
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
        )


async def _collect_once(app: Any, started_at: datetime) -> dict[str, Any]:
    started = time.perf_counter()
    first_batch = await asyncio.gather(
        _run_probe("llm", _probe_llm(app)),
        _run_probe("sqlite", _probe_sqlite()),
        _run_probe("chromadb", _probe_chromadb(app)),
        _run_probe("mcp", _probe_mcp(app)),
        _run_probe("threat_intel", _probe_threat_intel(app)),
        _run_probe("disk", _probe_disk()),
    )
    names = ("llm", "sqlite", "chromadb", "mcp", "threat_intel", "disk")
    checks = dict(zip(names, first_batch))
    sqlite_result = checks["sqlite"]
    background = await _run_probe(
        "background_work",
        _probe_background(
            sqlite_result.get("_analysis_counts", {}),
            getattr(app.state, "agent_store", None),
        ),
    )
    checks["background_work"] = background
    sqlite_result.pop("_analysis_counts", None)

    overall, summary = aggregate_status(checks)
    checked_at = _now_iso()
    return {
        "status": overall,
        "timestamp": checked_at,
        "version": HEALTH_VERSION,
        "uptime_seconds": round(
            (datetime.now(timezone.utc) - started_at).total_seconds(), 3
        ),
        "cached": False,
        "checked_at": checked_at,
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "summary": summary,
        "checks": checks,
    }


def clear_cache() -> None:
    global _cached_result, _cached_at, _last_probe_at
    _cached_result = None
    _cached_at = None
    _last_probe_at = None


async def get_detailed_health(
    app: Any,
    refresh: bool = False,
    started_at: datetime | None = None,
) -> dict[str, Any]:
    """Return a cached or freshly collected detailed health result."""
    global _cached_result, _cached_at, _last_probe_at
    started_at = started_at or _START_TIME
    now = time.monotonic()
    async with _cache_lock:
        cache_fresh = (
            _cached_result is not None
            and _cached_at is not None
            and now - _cached_at < CACHE_TTL_SECONDS
        )
        refresh_allowed = (
            _last_probe_at is None
            or now - _last_probe_at >= MIN_REFRESH_INTERVAL_SECONDS
        )
        if _cached_result is not None and (cache_fresh and not refresh):
            result = copy.deepcopy(_cached_result)
            result["cached"] = True
            return result
        if _cached_result is not None and refresh and not refresh_allowed:
            result = copy.deepcopy(_cached_result)
            result["cached"] = True
            return result

        result = await _collect_once(app, started_at)
        _cached_result = copy.deepcopy(result)
        _cached_at = time.monotonic()
        _last_probe_at = _cached_at
        return result
