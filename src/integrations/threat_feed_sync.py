"""Weekly, database-backed synchronization for public abuse.ch feeds.

Network functions are deliberately separate so callers and tests can replace
them without contacting either provider.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import aiohttp

from src.utils.api_key_validator import get_valid_key

logger = logging.getLogger(__name__)

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
THREATFOX_DAYS = 1
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
THREATFOX_LIMIT = 500
FEODO_LIMIT = 1000
RETENTION = timedelta(days=30)
SYNC_INTERVAL = timedelta(days=7)
RETRY_INTERVAL = timedelta(hours=1)
SYNC_LOCK = asyncio.Lock()
SOURCES = ("threatfox", "feodo")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def db_path_default() -> Path:
    return Path.home() / ".blue-team-assistant" / "cache" / "threat_feed.db"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
        except ValueError:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _connect(path: str | Path) -> sqlite3.Connection:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS threat_feed_items (
            source TEXT NOT NULL, ioc_type TEXT NOT NULL, ioc_value TEXT NOT NULL,
            malware TEXT, threat_type TEXT, confidence INTEGER, first_seen TEXT,
            last_seen TEXT, country TEXT, fetched_at TEXT NOT NULL,
            PRIMARY KEY(source, ioc_type, ioc_value)
        );
        CREATE TABLE IF NOT EXISTS threat_feed_state (
            source TEXT PRIMARY KEY, last_attempt_at TEXT NOT NULL,
            last_success_at TEXT, status TEXT NOT NULL, error_code TEXT,
            item_count INTEGER NOT NULL
        );
        """
    )
    return conn


def _safe_text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ord(ch) >= 32 and ord(ch) != 127).strip()
    return cleaned[:limit] if cleaned else None


def _normalize_ioc_type(value: Any) -> str:
    raw = value.lower() if isinstance(value, str) else ""
    if raw in {"ip:port", "ipv4:port", "ipv6:port"}:
        return "ip:port"
    if raw in {"ip", "ipv4", "ipv6", "ip_address"}:
        return "ip"
    if raw in {"domain", "hostname"}:
        return "domain"
    if raw in {"url", "uri"}:
        return "url"
    if raw.endswith("_hash") or raw in {"md5", "sha1", "sha256", "sha512"}:
        return "hash"
    return "other"


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None and str(value).strip() else None
    except (TypeError, ValueError, OverflowError):
        return None


def normalize_threatfox(payload: Any, fetched_at: str) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(payload, dict) or payload.get("query_status") not in {"ok", "no_result"}:
        raise ValueError("invalid ThreatFox response")
    records = payload.get("data")
    if payload.get("query_status") == "no_result" and records is None:
        records = []
    if not isinstance(records, list):
        raise ValueError("invalid ThreatFox records")
    result: list[dict[str, Any]] = []
    skipped = 0
    for row in records:
        if not isinstance(row, dict):
            skipped += 1
            continue
        value = _safe_text(row.get("ioc"), 300)
        if not value:
            skipped += 1
            continue
        result.append({
            "source": "threatfox",
            "ioc_type": _normalize_ioc_type(row.get("ioc_type")),
            "ioc_value": value,
            "malware": _safe_text(row.get("malware_printable") or row.get("malware"), 100),
            "threat_type": _safe_text(row.get("threat_type_desc") or row.get("threat_type"), 60),
            "confidence": _integer(row.get("confidence_level")),
            "first_seen": _safe_text(row.get("first_seen_utc") or row.get("first_seen"), 80) or "",
            "last_seen": _safe_text(row.get("last_seen_utc") or row.get("last_seen"), 80),
            "country": _safe_text(row.get("country"), 100),
            "fetched_at": fetched_at,
        })
    result.sort(
        key=lambda item: (
            (parsed := _parse_time(item["first_seen"])) is not None,
            parsed or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    return result[:THREATFOX_LIMIT], skipped


def normalize_feodo(payload: Any, fetched_at: str) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(payload, list):
        raise ValueError("invalid Feodo response")
    result: list[dict[str, Any]] = []
    skipped = 0
    for row in payload:
        if not isinstance(row, dict):
            skipped += 1
            continue
        value = _safe_text(row.get("ip_address"), 300)
        if not value:
            skipped += 1
            continue
        port = _safe_text(row.get("port"), 10)
        if port and port.isdigit() and ":" not in value:
            value = f"{value}:{port}"[:300]
        result.append({
            "source": "feodo",
            "ioc_type": "ip:port" if ":" in value and value.rsplit(":", 1)[1].isdigit() else "ip",
            "ioc_value": value,
            "malware": _safe_text(row.get("malware"), 100),
            "threat_type": _safe_text(row.get("threat_type"), 60),
            "confidence": _integer(row.get("confidence")),
            "first_seen": _safe_text(row.get("first_seen"), 80) or "",
            "last_seen": _safe_text(row.get("last_online"), 80),
            "country": _safe_text(row.get("country"), 100),
            "fetched_at": fetched_at,
        })
    result.sort(key=lambda item: item["first_seen"], reverse=True)
    return result[:FEODO_LIMIT], skipped


async def _read_response(response: aiohttp.ClientResponse) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.content.iter_chunked(64 * 1024):
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise FeedFetchError("response_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _request_json(source: str, *, api_keys: dict[str, Any] | None = None) -> Any:
    headers: dict[str, str] = {}
    if source == "threatfox":
        keys = api_keys if isinstance(api_keys, dict) else {}
        key = get_valid_key(keys, "threatfox") or get_valid_key(keys, "abusech")
        if not key:
            raise FeedFetchError("auth_key_missing")
        headers["Auth-Key"] = key
    timeout = aiohttp.ClientTimeout(total=20)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if source == "threatfox":
                async with session.post(
                    THREATFOX_URL,
                    json={"query": "get_iocs", "days": THREATFOX_DAYS},
                    headers=headers,
                ) as response:
                    raw = await _read_response(response)
            else:
                async with session.get(FEODO_URL) as response:
                    raw = await _read_response(response)
            if response.status != 200:
                raise FeedFetchError("http_401" if response.status == 401 else f"http_{response.status}")
            if len(raw) > MAX_RESPONSE_BYTES:
                raise FeedFetchError("response_too_large")
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise FeedFetchError("parse_error") from None
    except FeedFetchError:
        raise
    except (asyncio.TimeoutError, aiohttp.ServerTimeoutError):
        raise FeedFetchError("timeout") from None
    except (aiohttp.ClientError, OSError):
        raise FeedFetchError("network_error") from None


class FeedFetchError(Exception):
    """An error represented only by a safe, fixed code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


async def fetch_threatfox(api_keys: dict[str, Any] | None = None) -> Any:
    return await _request_json("threatfox", api_keys=api_keys)


async def fetch_feodo() -> Any:
    return await _request_json("feodo")


def _source_state_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    existing = {row["source"]: dict(row) for row in conn.execute("SELECT * FROM threat_feed_state")}
    return [existing.get(source, {
        "source": source, "status": "never_synced", "error_code": None,
        "last_success_at": None, "last_attempt_at": None, "item_count": 0,
    }) for source in SOURCES]


def get_sources(path: str | Path | None = None) -> list[dict[str, Any]]:
    conn = _connect(path or db_path_default())
    try:
        return _source_state_rows(conn)
    finally:
        conn.close()


def get_items(path: str | Path | None = None, limit: int = 10) -> list[dict[str, Any]]:
    conn = _connect(path or db_path_default())
    try:
        rows = conn.execute(
            "SELECT source, ioc_type, ioc_value, malware, threat_type, confidence, first_seen, country "
            "FROM threat_feed_items ORDER BY first_seen DESC LIMIT ?", (max(1, min(50, int(limit))),)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def due(source: str, path: str | Path | None = None, *, now: datetime | None = None) -> bool:
    if source not in SOURCES:
        return False
    now = now or utc_now()
    conn = _connect(path or db_path_default())
    try:
        row = conn.execute("SELECT last_attempt_at, last_success_at FROM threat_feed_state WHERE source=?", (source,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return True
    attempted = _parse_time(row["last_attempt_at"])
    succeeded = _parse_time(row["last_success_at"])
    retry_ready = attempted is None or now - attempted >= RETRY_INTERVAL
    weekly_due = succeeded is None or now - succeeded >= SYNC_INTERVAL
    return weekly_due and retry_ready


def _record_failure(path: str | Path, source: str, attempted: str, code: str) -> None:
    conn = _connect(path)
    try:
        prev = conn.execute("SELECT last_success_at FROM threat_feed_state WHERE source=?", (source,)).fetchone()
        count = conn.execute("SELECT COUNT(*) FROM threat_feed_items WHERE source=?", (source,)).fetchone()[0]
        conn.execute(
            "INSERT INTO threat_feed_state(source,last_attempt_at,last_success_at,status,error_code,item_count) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at, "
            "status=excluded.status,error_code=excluded.error_code,item_count=excluded.item_count",
            (source, attempted, prev[0] if prev else None, code, code, count),
        )
        conn.commit()
    finally:
        conn.close()


def _store_success(path: str | Path, source: str, items: list[dict[str, Any]], attempted: str) -> int:
    conn = _connect(path)
    try:
        with conn:
            if source == "feodo":
                keep = {(item["ioc_type"], item["ioc_value"]) for item in items}
                if keep:
                    existing = conn.execute("SELECT ioc_type,ioc_value FROM threat_feed_items WHERE source='feodo'").fetchall()
                    for old in existing:
                        if (old[0], old[1]) not in keep:
                            conn.execute("DELETE FROM threat_feed_items WHERE source='feodo' AND ioc_type=? AND ioc_value=?", tuple(old))
                else:
                    conn.execute("DELETE FROM threat_feed_items WHERE source='feodo'")
            conn.executemany(
                "INSERT INTO threat_feed_items(source,ioc_type,ioc_value,malware,threat_type,confidence,first_seen,last_seen,country,fetched_at) "
                "VALUES(:source,:ioc_type,:ioc_value,:malware,:threat_type,:confidence,:first_seen,:last_seen,:country,:fetched_at) "
                "ON CONFLICT(source,ioc_type,ioc_value) DO UPDATE SET malware=excluded.malware, threat_type=excluded.threat_type, "
                "confidence=excluded.confidence, first_seen=excluded.first_seen, last_seen=excluded.last_seen, "
                "country=excluded.country, fetched_at=excluded.fetched_at", items,
            )
            cutoff = _iso((utc_now() if not attempted else _parse_time(attempted) or utc_now()) - RETENTION)
            conn.execute("DELETE FROM threat_feed_items WHERE source=? AND fetched_at < ?", (source, cutoff))
            count = conn.execute("SELECT COUNT(*) FROM threat_feed_items WHERE source=?", (source,)).fetchone()[0]
            conn.execute(
                "INSERT INTO threat_feed_state(source,last_attempt_at,last_success_at,status,error_code,item_count) "
                "VALUES(?,?,?,'ok',NULL,?) ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at, "
                "last_success_at=excluded.last_success_at,status='ok',error_code=NULL,item_count=excluded.item_count",
                (source, attempted, attempted, count),
            )
        return count
    finally:
        conn.close()


async def sync_source(source: str, config: dict[str, Any] | None, path: str | Path | None = None,
                      *, now_fn: Callable[[], datetime] = utc_now) -> dict[str, Any]:
    if source not in SOURCES:
        raise ValueError("unknown feed source")
    target = path or db_path_default()
    now = _iso(now_fn())
    api_keys = config.get("api_keys", {}) if isinstance(config, dict) else {}
    try:
        payload = await fetch_threatfox(api_keys) if source == "threatfox" else await fetch_feodo()
        items, skipped = normalize_threatfox(payload, now) if source == "threatfox" else normalize_feodo(payload, now)
        count = _store_success(target, source, items, now)
        if skipped:
            logger.info("Threat feed %s skipped %d malformed rows", source, skipped)
        return {"source": source, "status": "ok", "error_code": None, "item_count": count}
    except FeedFetchError as exc:
        code = exc.code
    except (ValueError, TypeError, KeyError):
        code = "parse_error"
    except Exception:
        code = "network_error"
    _record_failure(target, source, now, code)
    return next(state for state in get_sources(target) if state["source"] == source)


async def sync_all(config: dict[str, Any] | None, path: str | Path | None = None,
                   *, now_fn: Callable[[], datetime] = utc_now) -> list[dict[str, Any]] | None:
    if SYNC_LOCK.locked():
        return None
    await SYNC_LOCK.acquire()
    try:
        for source in SOURCES:
            await sync_source(source, config, path, now_fn=now_fn)
        return get_sources(path)
    finally:
        SYNC_LOCK.release()


async def sync_due(config: dict[str, Any] | None, path: str | Path | None = None,
                   *, now_fn: Callable[[], datetime] = utc_now) -> list[dict[str, Any]] | None:
    if SYNC_LOCK.locked():
        return None
    await SYNC_LOCK.acquire()
    try:
        now = now_fn()
        for source in SOURCES:
            if due(source, path, now=now):
                await sync_source(source, config, path, now_fn=now_fn)
        return get_sources(path)
    finally:
        SYNC_LOCK.release()


def sync_enabled() -> bool:
    return (os.environ.get("CABTA_THREAT_FEED_SYNC") != "0"
            and "PYTEST_CURRENT_TEST" not in os.environ
            and "pytest" not in sys.modules)


async def run_sync_loop(app: Any, *, sleep: Callable[[float], Any] = asyncio.sleep,
                        now_fn: Callable[[], datetime] = utc_now) -> None:
    await sleep(60)
    while True:
        try:
            await sync_due(getattr(app.state, "config", {}), getattr(app.state, "threat_feed_db_path", None), now_fn=now_fn)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.error("Threat feed scheduled sync failed")
        await sleep(3600)
