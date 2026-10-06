"""Encrypted storage and bounded cross-check lookups for user-owned API keys."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken


ALLOWED_SOURCES = ("virustotal", "abuseipdb", "otx")
ENCRYPTION_KEY_ENV = "USER_API_KEY_ENCRYPTION_KEY"
DISABLED_REASON = "Personal API keys are not enabled on this server."
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class UserApiKeyEncryptionUnavailable(RuntimeError):
    """Raised when the dedicated at-rest encryption key is unavailable."""


class UserApiKeyCipher:
    def __init__(self, key: bytes | str | None = None):
        if key is None:
            key = os.getenv(ENCRYPTION_KEY_ENV)
        if not key:
            raise UserApiKeyEncryptionUnavailable
        try:
            if isinstance(key, str):
                key = key.encode("ascii")
            self._fernet = Fernet(key)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise UserApiKeyEncryptionUnavailable from exc

    def encrypt(self, api_key: str) -> str:
        return self._fernet.encrypt(api_key.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError) as exc:
            raise UserApiKeyEncryptionUnavailable from exc


def _auth_db_path() -> Path:
    return Path(os.getenv("AUTH_DB_PATH", "src/db/auth.db"))


def _upgrade(connection: sqlite3.Connection) -> None:
    migration_path = PROJECT_ROOT / "src" / "db" / "migrations" / "014_add_user_api_keys.py"
    spec = importlib.util.spec_from_file_location("_user_api_keys_migration_014", migration_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("User API key migration is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.upgrade(connection)


def _connect() -> sqlite3.Connection:
    path = _auth_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _validate_source(source: str) -> None:
    if source not in ALLOWED_SOURCES:
        raise ValueError("Unsupported source")


class UserApiKeyStore:
    """Owner-scoped key metadata and ciphertext persistence."""

    def list_metadata(self, user_id: int) -> list[dict[str, Any]]:
        with _connect() as connection:
            _upgrade(connection)
            rows = connection.execute(
                "SELECT source, last_used_at FROM user_api_keys WHERE user_id = ? ORDER BY source",
                (int(user_id),),
            ).fetchall()
        configured = {row["source"]: row["last_used_at"] for row in rows}
        return [
            {"source": source, "configured": source in configured,
             "last_used_at": configured.get(source)}
            for source in ALLOWED_SOURCES
        ]

    def save(self, user_id: int, source: str, api_key: str) -> None:
        _validate_source(source)
        encrypted = UserApiKeyCipher().encrypt(api_key)
        with _connect() as connection:
            _upgrade(connection)
            connection.execute(
                """INSERT INTO user_api_keys(user_id, source, encrypted_key)
                   VALUES (?, ?, ?)
                   ON CONFLICT(user_id, source) DO UPDATE SET encrypted_key = excluded.encrypted_key""",
                (int(user_id), source, encrypted),
            )
            connection.commit()

    def delete(self, user_id: int, source: str) -> bool:
        _validate_source(source)
        with _connect() as connection:
            _upgrade(connection)
            cursor = connection.execute(
                "DELETE FROM user_api_keys WHERE user_id = ? AND source = ?",
                (int(user_id), source),
            )
            connection.commit()
            return cursor.rowcount > 0

    def keys_for_lookup(self, user_id: int) -> dict[str, str]:
        with _connect() as connection:
            _upgrade(connection)
            rows = connection.execute(
                "SELECT source, encrypted_key FROM user_api_keys WHERE user_id = ?",
                (int(user_id),),
            ).fetchall()
        if not rows:
            return {}
        cipher = UserApiKeyCipher()
        output = {row["source"]: cipher.decrypt(row["encrypted_key"]) for row in rows}
        return output

    def mark_used(self, user_id: int, source: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with _connect() as connection:
            _upgrade(connection)
            connection.execute(
                "UPDATE user_api_keys SET last_used_at = ? WHERE user_id = ? AND source = ?",
                (timestamp, int(user_id), source),
            )
            connection.commit()


def _ioc_kind(ioc_type: str, ioc: str) -> str:
    kind = (ioc_type or "").lower().replace("_", "").replace("-", "")
    aliases = {
        "ipv4": "ip", "ipv6": "ipv6", "ipaddress": "ip", "ip": "ip",
        "domain": "domain", "hostname": "domain", "url": "url",
        "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
        "hash": "hash", "hashmd5": "hash", "hashsha1": "hash",
        "hashsha256": "hash", "filehash": "hash",
    }
    if kind in aliases:
        return aliases[kind]
    if ":" in ioc:
        return "ipv6"
    if ioc.count(".") == 3 and all(part.isdigit() for part in ioc.split(".")):
        return "ip"
    return "unknown"


def _safe_result(source: str, status: str, **summary: Any) -> dict[str, Any]:
    allowed_fields = {
        "virustotal": {"malicious", "suspicious", "total_engines"},
        "abuseipdb": {"confidence", "reports", "country"},
        "otx": {"pulses", "reputation"},
    }[source]
    safe_summary = {}
    for key, value in summary.items():
        if key not in allowed_fields:
            continue
        if isinstance(value, str):
            safe_summary[key] = value[:80]
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            safe_summary[key] = value
    item = {"source": source, "status": status}
    if safe_summary:
        item["summary"] = safe_summary
    return item


async def _provider_lookup(source: str, api_key: str, ioc: str, ioc_type: str) -> dict[str, Any]:
    """Call one fixed provider endpoint; response fields are strictly summarized."""
    import aiohttp

    kind = _ioc_kind(ioc_type, ioc)
    if kind == "unknown":
        return _safe_result(source, "not_applicable")
    timeout = aiohttp.ClientTimeout(total=5, connect=3, sock_read=4)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if source == "virustotal":
                indicator = ioc
                if kind == "url":
                    indicator = base64.urlsafe_b64encode(ioc.encode("utf-8")).decode("ascii").rstrip("=")
                vt_kind = {"ip": "ip_addresses", "ipv6": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}[kind]
                endpoint = f"https://www.virustotal.com/api/v3/{vt_kind}/{quote(indicator, safe='')}"
                headers = {"x-apikey": api_key}
                async with session.get(endpoint, headers=headers) as response:
                    if response.status == 404:
                        return _safe_result(source, "not_found")
                    if response.status != 200:
                        return _safe_result(source, "unavailable")
                    payload = await response.json(content_type=None)
                stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return _safe_result(source, "available", malicious=stats.get("malicious"),
                                    suspicious=stats.get("suspicious"),
                                    total_engines=sum(v for v in stats.values() if isinstance(v, int)))
            if source == "abuseipdb":
                if kind not in {"ip", "ipv6"}:
                    return _safe_result(source, "not_applicable")
                endpoint = "https://api.abuseipdb.com/api/v2/check"
                headers = {"Key": api_key, "Accept": "application/json"}
                params = {"ipAddress": ioc, "maxAgeInDays": "90"}
                async with session.get(endpoint, headers=headers, params=params) as response:
                    if response.status != 200:
                        return _safe_result(source, "unavailable")
                    payload = await response.json(content_type=None)
                data = payload.get("data", {})
                return _safe_result(source, "available", confidence=data.get("abuseConfidenceScore"),
                                    reports=data.get("totalReports"), country=data.get("countryCode"))
            if source == "otx":
                otx_kind = {"ip": "IPv4", "ipv6": "IPv6", "domain": "domain", "hash": "file", "url": "url"}[kind]
                endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_kind}/{quote(ioc, safe='')}/general"
                headers = {"X-OTX-API-KEY": api_key}
                async with session.get(endpoint, headers=headers) as response:
                    if response.status == 404:
                        return _safe_result(source, "not_found")
                    if response.status != 200:
                        return _safe_result(source, "unavailable")
                    payload = await response.json(content_type=None)
                pulse_info = payload.get("pulse_info", {})
                return _safe_result(source, "available", pulses=pulse_info.get("count"),
                                    reputation=payload.get("reputation"))
    except (asyncio.TimeoutError, Exception):
        return _safe_result(source, "unavailable")
    return _safe_result(source, "unavailable")


async def cross_check_ioc(
    ioc: str, ioc_type: str, user_id: int | None, store: UserApiKeyStore | None = None,
) -> list[dict[str, Any]]:
    """Run post-investigation enrichment using only this user's configured keys."""
    if user_id is None:
        return []
    store = store or UserApiKeyStore()
    try:
        keys = store.keys_for_lookup(user_id)
    except UserApiKeyEncryptionUnavailable:
        return [_safe_result(source, "unavailable") for source in ALLOWED_SOURCES]
    output = []
    for source in ALLOWED_SOURCES:
        api_key = keys.get(source)
        if not api_key:
            continue
        try:
            store.mark_used(user_id, source)
            output.append(await _provider_lookup(source, api_key, ioc, ioc_type))
        except Exception:
            output.append(_safe_result(source, "unavailable"))
    return output
