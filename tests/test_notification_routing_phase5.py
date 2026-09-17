"""Phase 5 notification-routing negative/security tests."""

from __future__ import annotations

import importlib.util
import json
import logging
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.integrations.notification_policy import (
    EVENT_ROLE_MAP,
    NotificationStore,
    event_frequency,
    make_dedup_key,
    resolve_recipients,
)
from src.integrations.notifications import NotificationManager
from src.web.gmail_sender import GmailSender
from src.web.notification_recipients import get_active_users_with_gmail


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"


def _load_migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _auth_db(path: Path) -> None:
    for filename in (
        "001_create_users.py",
        "002_add_username_and_admin_role.py",
        "004_add_team_lead_role.py",
        "007_add_gmail_oauth.py",
        "008_add_notification_dedup.py",
    ):
        _load_migration(filename).migrate(str(path))


def _users(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executemany(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                ("soc@example.test", "soc", "hash", "SOC Analyst Tier 1-2", 1),
                ("ir@example.test", "ir", "hash", "Incident Responder", 1),
                ("hunter@example.test", "hunter", "hash", "Threat Hunter", 1),
                ("lead@example.test", "lead", "hash", "Team Lead", 1),
                ("inactive@example.test", "inactive", "hash", "SOC Analyst Tier 1-2", 0),
            ],
        )
        connection.execute(
            "INSERT INTO user_gmail_tokens "
            "(user_id, google_subject, google_email, refresh_token_ciphertext, "
            "token_key_version, granted_scopes) VALUES (1, 's', 'soc@gmail.com', 'c', 1, '[]')"
        )
        connection.execute(
            "INSERT INTO user_gmail_tokens "
            "(user_id, google_subject, google_email, refresh_token_ciphertext, "
            "token_key_version, granted_scopes) VALUES (2, 'i', 'ir@gmail.com', 'c', 1, '[]')"
        )
        connection.execute(
            "INSERT INTO user_gmail_tokens "
            "(user_id, google_subject, google_email, refresh_token_ciphertext, "
            "token_key_version, granted_scopes, revoked_at) "
            "VALUES (4, 'l', 'lead@gmail.com', 'c', 1, '[]', 'now')"
        )
        connection.commit()


def test_migration_008_is_idempotent_and_unique(tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    _load_migration("008_add_notification_dedup.py").migrate(str(db_path))

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"notification_dedup", "notification_digest_queue"} <= tables
        connection.execute(
            "INSERT INTO notification_dedup "
            "(dedup_key, recipient_user_id, event_type, payload_summary, "
            "first_seen_at, last_seen_at, expires_at) "
            "VALUES ('k', 1, 'verdict_alert', '{}', 'a', 'a', 'z')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO notification_dedup "
                "(dedup_key, recipient_user_id, event_type, payload_summary, "
                "first_seen_at, last_seen_at, expires_at) "
                "VALUES ('k', 1, 'verdict_alert', '{}', 'a', 'a', 'z')"
            )


def test_role_policy_isolation_and_action_direct_recipient(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    _users(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))

    recipients = resolve_recipients("verdict_alert", {"verdict": "MALICIOUS"})
    assert recipients == [1, 4]
    assert EVENT_ROLE_MAP["verdict_alert"] == ["SOC Analyst Tier 1-2", "Team Lead"]
    assert 2 not in recipients and 3 not in recipients
    assert resolve_recipients("approval_required", {}) == [2]
    assert resolve_recipients("action_executed", {"approved_by": 2}) == [2]
    assert resolve_recipients("action_executed", {}) == []
    assert resolve_recipients("unrecognized", {}) == []
    assert event_frequency("action_executed", {}) == "realtime"


def test_active_recipient_resolver_exposes_linked_status_and_excludes_inactive(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    _users(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))

    rows = get_active_users_with_gmail("SOC Analyst Tier 1-2")
    assert rows == [{"user_id": 1, "email": "soc@gmail.com", "gmail_linked": True}]


def test_gmail_sender_skips_missing_revoked_and_refresh_failure_without_leaking(monkeypatch, caplog):
    class Service:
        def get_status(self, user_id):
            return {"linked": False, "revoked": False, "google_email": None}

        def refresh_access_token(self, user_id):
            raise AssertionError("must not refresh an unlinked account")

    sender = GmailSender(service=Service())
    assert sender.send_email(9, "subject", "body")["success"] is False

    class RevokedService(Service):
        def get_status(self, user_id):
            return {"linked": True, "revoked": True, "google_email": "x@gmail.com"}

    assert GmailSender(service=RevokedService()).send_email(9, "s", "b")["success"] is False

    class BrokenService(Service):
        calls = 0

        def get_status(self, user_id):
            return {"linked": True, "revoked": False, "google_email": "x@gmail.com"}

        def refresh_access_token(self, user_id):
            self.calls += 1
            raise RuntimeError("refresh secret should not be logged")

    broken = BrokenService()
    with caplog.at_level(logging.WARNING):
        result = GmailSender(service=broken).send_email(9, "s", "b")
    assert result["success"] is False
    assert broken.calls == 1  # no retry is performed by the adapter
    assert "refresh secret" not in caplog.text


def test_gmail_sender_uses_mocked_gmail_api(monkeypatch):
    class Credentials:
        pass

    class Service:
        def get_status(self, user_id):
            return {"linked": True, "revoked": False, "google_email": "x@gmail.com"}

        def refresh_access_token(self, user_id):
            return Credentials()

    sent = {}

    class Messages:
        def send(self, **kwargs):
            sent.update(kwargs)
            return SimpleNamespace(execute=lambda: {"id": "message-id"})

    class Users:
        def messages(self):
            return Messages()

    sender = GmailSender(service=Service(), build_client=lambda *args, **kwargs: SimpleNamespace(users=lambda: Users()))
    assert sender.send_email(1, "subject", "body")["success"] is True
    assert sent["userId"] == "me"
    assert set(sent["body"]) == {"raw"}


def test_dedup_expires_after_five_minutes(tmp_path):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    _users(db_path)
    from datetime import datetime, timedelta, timezone

    store = NotificationStore(str(db_path))
    key = make_dedup_key("verdict_alert", {"ioc": "EXAMPLE.com", "verdict": "MALICIOUS"}, 1)
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert store.should_dedup(key, 1, "verdict_alert", {}, now=first) is False
    assert store.should_dedup(key, 1, "verdict_alert", {}, now=first + timedelta(minutes=4)) is True
    assert store.should_dedup(key, 1, "verdict_alert", {}, now=first + timedelta(minutes=5, seconds=1)) is False


def test_dedup_window_and_digest_queue(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    _users(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    manager = NotificationManager({"notifications": {"enabled": True}})
    sent = []
    manager.gmail_sender.send_email = lambda user_id, subject, body: sent.append((user_id, subject, body)) or {"success": True}

    payload = {"ioc": "Example.COM", "verdict": "MALICIOUS", "threat_score": 95}
    manager.notify("verdict_alert", payload)
    manager.notify("verdict_alert", payload)
    assert len(sent) == 2

    manager.notify("verdict_alert", {"ioc": "Example.COM", "verdict": "SUSPICIOUS", "threat_score": 65})
    assert len(sent) == 2
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM notification_digest_queue WHERE sent_at IS NULL"
        ).fetchone()[0] == 2
    manager.send_pending_digests()
    assert len(sent) == 4
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM notification_digest_queue WHERE sent_at IS NOT NULL"
        ).fetchone()[0] == 2
        summary = connection.execute(
            "SELECT payload_summary FROM notification_digest_queue"
        ).fetchone()[0]
        assert "Example.COM" not in summary


def test_smtp_and_line_channels_remain_parallel(monkeypatch):
    class Channel:
        def __init__(self):
            self.calls = 0

        def send(self, subject, body):
            self.calls += 1
            return {"success": True}

    manager = NotificationManager({"notifications": {"enabled": True}})
    smtp = Channel()
    line = Channel()
    manager.channels = [smtp, line]
    manager.gmail_sender = None
    manager.notify("verdict_alert", {"ioc": "x", "verdict": "MALICIOUS"})
    assert smtp.calls == 1 and line.calls == 1


def test_unknown_event_and_unlinked_recipient_are_safe_and_structured(tmp_path, monkeypatch, caplog):
    db_path = tmp_path / "auth.db"
    _auth_db(db_path)
    _users(db_path)
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    with sqlite3.connect(db_path) as connection:
        connection.execute("DELETE FROM user_gmail_tokens WHERE user_id = 2")
        connection.commit()
    manager = NotificationManager({"notifications": {"enabled": True}})
    original_sender = manager.gmail_sender.send_email
    manager.gmail_sender.send_email = lambda *args: pytest.fail("unknown event must not deliver")
    assert manager.notify("new_future_event", {"secret": "not logged"}) == []
    manager.gmail_sender.send_email = original_sender

    with caplog.at_level(logging.INFO):
        result = manager.notify(
            "approval_required", {"tool": "contain", "session_id": "s-1"}
        )
    assert result and result[0]["success"] is False
    assert "gmail_not_linked" in caplog.text
    assert "not logged" not in caplog.text


def test_direct_flow_a_triggers_notification(monkeypatch):
    from src.tools.ioc_investigator import IOCInvestigator
    from src.tools.malware_analyzer import MalwareAnalyzer

    ioc_manager = SimpleNamespace(notify=lambda event, payload: calls.append((event, payload)))
    calls = []
    investigator = IOCInvestigator({"analysis": {"enable_llm": False}}, notification_manager=ioc_manager)
    investigator._trusted_infrastructure_match = lambda *args: None
    investigator.threat_intel.investigate_ioc_comprehensive = lambda *args, **kwargs: _FakeAwaitable({
        "sources": {"test": {"malicious": True}}, "sources_checked": 1, "sources_flagged": 1
    })
    monkeypatch.setattr("src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score", lambda _: 95)
    monkeypatch.setattr("src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage", lambda _: 1.0)
    monkeypatch.setattr("src.tools.ioc_investigator.determine_verdict", lambda score, coverage: "MALICIOUS")

    import asyncio
    asyncio.run(investigator.investigate("1.2.3.4"))
    assert calls and calls[0][0] == "verdict_alert"

    malware = MalwareAnalyzer.__new__(MalwareAnalyzer)
    malware.notification_manager = ioc_manager
    malware._notify_verdict("sample.bin", "SUSPICIOUS", 65, "analysis-2", "abc123")
    assert calls[-1][0] == "verdict_alert"
    assert calls[-1][1]["verdict"] == "SUSPICIOUS"


class _FakeAwaitable:
    def __init__(self, value):
        self.value = value

    def __await__(self):
        async def _value():
            return self.value

        return _value().__await__()
