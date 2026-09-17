"""Phase 5 notification routing, frequency, and transactional dedup policy."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from src.web.auth import _connect, get_active_user
from src.web.notification_recipients import get_active_users_with_gmail

EVENT_ROLE_MAP = {
    "verdict_alert": ["SOC Analyst Tier 1-2", "Team Lead"],
    "approval_required": ["Incident Responder"],
}

FREQUENCY_MAP = {
    "MALICIOUS": "realtime",
    "SUSPICIOUS": "digest",
    "CLEAN": "none",
    "UNKNOWN": "none",
    "approval_required": "realtime",
    "action_executed": "realtime",
}

DEDUP_WINDOW_SECONDS = 5 * 60
DIGEST_INTERVAL_SECONDS = 15 * 60


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _utc_now()).strftime("%Y-%m-%d %H:%M:%S")


def normalize_ioc(value: Any) -> str:
    """Normalize an IOC for stable deduplication without changing its display."""
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        try:
            parsed = urlsplit(text)
            hostname = (parsed.hostname or "").rstrip(".")
            netloc = hostname
            if parsed.port:
                netloc = f"{hostname}:{parsed.port}"
            text = urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/"), parsed.query, ""))
        except ValueError:
            pass
    return re.sub(r"\s+", "", text).rstrip(".")


def event_frequency(event_type: str, payload: dict | None) -> str:
    payload = payload or {}
    if event_type in ("approval_required", "action_executed"):
        return FREQUENCY_MAP[event_type]
    if event_type != "verdict_alert":
        return "none"
    return FREQUENCY_MAP.get(str(payload.get("verdict", "UNKNOWN")).upper(), "none")


def resolve_recipients(event_type: str, payload: dict | None) -> list[int]:
    """Resolve policy recipients; action execution is always owner-directed."""
    payload = payload or {}
    if event_type == "action_executed":
        try:
            approved_by = int(payload.get("approved_by"))
        except (TypeError, ValueError):
            return []
        if approved_by <= 0:
            return []
        try:
            return [approved_by] if get_active_user(approved_by) is not None else []
        except sqlite3.OperationalError:
            return []
    roles = EVENT_ROLE_MAP.get(event_type, [])
    recipients: list[int] = []
    for role in roles:
        recipients.extend(int(row["user_id"]) for row in get_active_users_with_gmail(role))
    return list(dict.fromkeys(recipients))


def make_dedup_key(event_type: str, payload: dict | None, recipient_user_id: int) -> str:
    payload = payload or {}
    verdict = str(payload.get("verdict", "")).strip().upper()
    ioc = normalize_ioc(payload.get("ioc") or payload.get("normalized_ioc"))
    return f"{event_type}|{verdict}|{ioc}|{int(recipient_user_id)}"


def payload_summary(payload: dict | None) -> dict[str, Any]:
    """Create a small JSON-safe summary; raw IOC and other sensitive fields are omitted."""
    payload = payload or {}
    summary: dict[str, Any] = {}
    for key in (
        "verdict", "ioc_type", "threat_score", "session_id", "analysis_id",
        "tool", "status", "approved_by", "actor", "owner",
    ):
        value = payload.get(key)
        if isinstance(value, (str, int, float, bool)) and len(str(value)) <= 500:
            summary[key] = value
    if payload.get("ioc"):
        summary["ioc_sha256"] = hashlib.sha256(str(payload["ioc"]).encode("utf-8")).hexdigest()
    return summary


class NotificationStore:
    """SQLite repository; claim operations are serialized with BEGIN IMMEDIATE."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path
        self._ensure_schema()

    def _connection(self):
        connection = _connect() if self.db_path is None else sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _ensure_schema(self) -> None:
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / "db" / "migrations" / "008_add_notification_dedup.py"
        spec = importlib.util.spec_from_file_location("notification_dedup_migration", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Unable to load notification migration")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if self.db_path is None:
            # Migration 008 resolves AUTH_DB_PATH itself.
            module.migrate()
        else:
            module.migrate(self.db_path)

    def should_dedup(
        self,
        dedup_key: str,
        recipient_user_id: int,
        event_type: str,
        summary: dict[str, Any],
        now: datetime | None = None,
    ) -> bool:
        current = now or _utc_now()
        current_text = _timestamp(current)
        expiry = _timestamp(current + timedelta(seconds=DEDUP_WINDOW_SECONDS))
        encoded = json.dumps(summary, sort_keys=True, separators=(",", ":"))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT expires_at FROM notification_dedup WHERE dedup_key = ?",
                (dedup_key,),
            ).fetchone()
            if row is not None and str(row["expires_at"]) > current_text:
                connection.execute(
                    "UPDATE notification_dedup SET last_seen_at = ? WHERE dedup_key = ?",
                    (current_text, dedup_key),
                )
                connection.commit()
                return True
            if row is None:
                connection.execute(
                    "INSERT INTO notification_dedup "
                    "(dedup_key, recipient_user_id, event_type, payload_summary, "
                    "first_seen_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (dedup_key, int(recipient_user_id), event_type, encoded, current_text, current_text, expiry),
                )
            else:
                connection.execute(
                    "UPDATE notification_dedup SET recipient_user_id = ?, event_type = ?, "
                    "payload_summary = ?, first_seen_at = ?, last_seen_at = ?, sent_at = NULL, expires_at = ? "
                    "WHERE dedup_key = ?",
                    (int(recipient_user_id), event_type, encoded, current_text, current_text, expiry, dedup_key),
                )
            connection.commit()
        return False

    def mark_sent(self, dedup_key: str, now: datetime | None = None) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE notification_dedup SET sent_at = ? WHERE dedup_key = ?",
                (_timestamp(now), dedup_key),
            )
            connection.commit()

    def enqueue_digest(self, recipient_user_id: int, event_type: str, summary: dict[str, Any], now: datetime | None = None) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO notification_digest_queue "
                "(recipient_user_id, event_type, payload_summary, queued_at) VALUES (?, ?, ?, ?)",
                (int(recipient_user_id), event_type, json.dumps(summary, sort_keys=True), _timestamp(now)),
            )
            connection.commit()

    def pending_digest(self) -> list[sqlite3.Row]:
        with self._connection() as connection:
            return connection.execute(
                "SELECT id, recipient_user_id, event_type, payload_summary "
                "FROM notification_digest_queue WHERE sent_at IS NULL ORDER BY recipient_user_id, id"
            ).fetchall()

    def mark_digest_sent(self, ids: list[int], now: datetime | None = None) -> None:
        if not ids:
            return
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            marks = ",".join("?" for _ in ids)
            connection.execute(
                f"UPDATE notification_digest_queue SET sent_at = ? WHERE id IN ({marks}) AND sent_at IS NULL",
                [_timestamp(now), *[int(item) for item in ids]],
            )
            connection.commit()


def should_dedup(
    dedup_key: str,
    recipient_user_id: int = 0,
    event_type: str = "unknown",
    summary: dict[str, Any] | None = None,
    db_path: str | None = None,
) -> bool:
    """Public convenience wrapper: True means a notification is suppressed."""
    return NotificationStore(db_path).should_dedup(
        dedup_key, recipient_user_id, event_type, summary or {}
    )
