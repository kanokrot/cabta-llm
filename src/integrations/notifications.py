"""
Notification integrations - Email (SMTP) and LINE Messaging API.

Provides a small ``NotificationManager`` that fans out alert-style events
(high-severity verdicts, approval checkpoints, executed actions) to whatever
channels are enabled in ``config['notifications']``. Designed to never raise:
failures are logged and swallowed so a broken/unconfigured channel can't take
down the agent loop or a playbook run.
"""

import logging
import json
import os
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, List, Tuple

import requests

from .notification_policy import (
    NotificationStore,
    event_frequency,
    make_dedup_key,
    payload_summary,
    resolve_recipients,
)
from ..web.gmail_sender import GmailSender

logger = logging.getLogger(__name__)


class NotificationChannel:
    """Abstract base -- every channel implements ``.send(subject, message)``."""

    def send(self, subject: str, message: str) -> dict:
        """Send a notification. Must return a ``{"success": bool, ...}`` dict."""
        raise NotImplementedError


class EmailChannel(NotificationChannel):
    """Sends notifications via SMTP using the standard library ``smtplib``."""

    def __init__(self, cfg: dict):
        """
        Parameters
        ----------
        cfg : dict
            ``config['notifications']['email']`` -- expects ``smtp_host``,
            ``smtp_port``, ``smtp_user``, ``smtp_password``, ``from_addr``,
            and ``to_addrs`` (list of recipient addresses).
        """
        cfg = cfg or {}
        self.smtp_host = cfg.get("smtp_host", "")
        self.smtp_port = cfg.get("smtp_port", 587)
        self.smtp_user = cfg.get("smtp_user", "")
        self.smtp_password = cfg.get("smtp_password", "")
        self.from_addr = cfg.get("from_addr", "")
        self.to_addrs = cfg.get("to_addrs", []) or []

    def send(self, subject: str, message: str) -> dict:
        """Send *subject*/*message* to all configured recipients via SMTP+STARTTLS.

        Returns ``{"success": False, "error": "not configured"}`` without
        raising when ``smtp_host`` is empty (e.g. credentials not filled in
        yet for a demo).
        """
        if not self.smtp_host:
            return {"success": False, "error": "not configured"}

        try:
            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.starttls()
                if self.smtp_user:
                    server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())

            return {"success": True}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


class LineChannel(NotificationChannel):
    """Sends notifications via the LINE Messaging API push endpoint."""

    def __init__(self, cfg: dict):
        """
        Parameters
        ----------
        cfg : dict
            ``config['notifications']['line']`` -- expects
            ``channel_access_token`` and ``to_user_id``.
        """
        cfg = cfg or {}
        self.channel_access_token = cfg.get("channel_access_token", "")
        self.to_user_id = cfg.get("to_user_id", "")

    def send(self, subject: str, message: str) -> dict:
        """Push *subject*/*message* (joined into one text) to ``to_user_id``.

        Returns ``{"success": False, "error": "not configured"}`` without
        raising when ``channel_access_token`` is empty.
        """
        if not self.channel_access_token:
            return {"success": False, "error": "not configured"}

        text = f"{subject}\n{message}" if subject else message

        try:
            response = requests.post(
                "https://api.line.me/v2/bot/message/push",
                headers={
                    "Authorization": f"Bearer {self.channel_access_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "to": self.to_user_id,
                    "messages": [{"type": "text", "text": text}],
                },
                timeout=10,
            )
            if response.status_code == 200:
                return {"success": True}
            return {
                "success": False,
                "error": f"LINE API returned {response.status_code}: {response.text[:200]}",
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}


class NotificationManager:
    """Central dispatch point used by ``agent_loop.py`` / ``playbook_engine.py``."""

    def __init__(self, config: dict):
        """
        Parameters
        ----------
        config : dict
            The full application config dict (same shape ``AgentLoop``
            receives). Reads ``config['notifications']``. If ``enabled`` is
            not ``True``, no channels are created and ``notify()`` becomes a
            no-op.
        """
        notif_cfg = (config or {}).get("notifications", {}) or {}

        self.enabled = notif_cfg.get("enabled") is True
        self.create_on_verdict = notif_cfg.get("create_on_verdict", []) or []
        self.channels: List[NotificationChannel] = []
        self.gmail_sender = None
        self.notification_store = None

        if not self.enabled:
            return

        email_cfg = notif_cfg.get("email", {}) or {}
        if email_cfg.get("enabled"):
            self.channels.append(EmailChannel(email_cfg))

        line_cfg = notif_cfg.get("line", {}) or {}
        if line_cfg.get("enabled"):
            self.channels.append(LineChannel(line_cfg))

        # Gmail is a parallel per-user channel. It is enabled by default when
        # the notification system is enabled; an explicit false can disable it
        # without changing the legacy SMTP/LINE settings.
        gmail_cfg = notif_cfg.get("gmail", {}) or {}
        if gmail_cfg.get("enabled", True):
            try:
                self.gmail_sender = GmailSender(db_path=os.getenv("AUTH_DB_PATH"))
                self.notification_store = NotificationStore(db_path=os.getenv("AUTH_DB_PATH"))
            except Exception:
                # Gmail is optional; SMTP/LINE must remain available if local
                # OAuth/database provisioning is incomplete.
                logger.warning("[NOTIFY] Gmail channel unavailable")
                self.gmail_sender = None
                self.notification_store = None

    def notify(self, event_type: str, payload: dict) -> list:
        """
        Format and send an alert to every enabled channel.

        Parameters
        ----------
        event_type : str
            One of ``"verdict_alert"``, ``"approval_required"``, or
            ``"action_executed"``.
        payload : dict
            Event-specific fields, e.g. ``{"ioc": ..., "verdict": ...,
            "session_id": ..., "tool": ..., "description": ..., "status": ...}``.

        Returns
        -------
        list
            The ``send()`` result dict from each channel (for debugging/logging).
            Never raises -- a failing channel is logged and skipped so the
            caller (agent loop / playbook engine) always keeps running.
        """
        results: List[Dict[str, Any]] = []

        if not self.channels and self.gmail_sender is None:
            return results

        subject, message = self._format_message(event_type, payload)

        for channel in self.channels:
            try:
                result = channel.send(subject, message)
            except Exception as exc:
                result = {"success": False, "error": str(exc)}

            if not result.get("success"):
                logger.warning(
                    "[NOTIFY] %s via %s failed: %s",
                    event_type, type(channel).__name__, result.get("error"),
                )
            else:
                logger.info(
                    "[NOTIFY] %s sent via %s", event_type, type(channel).__name__,
                )

            results.append(result)

        self._notify_gmail(event_type, payload, subject, message, results)

        return results

    def _notify_gmail(
        self,
        event_type: str,
        payload: dict,
        subject: str,
        message: str,
        results: List[Dict[str, Any]],
    ) -> None:
        """Route policy events to linked users without affecting legacy channels."""
        if self.gmail_sender is None or self.notification_store is None:
            return
        frequency = event_frequency(event_type, payload)
        if frequency == "none":
            return
        summary = payload_summary(payload)
        for recipient_user_id in resolve_recipients(event_type, payload):
            dedup_key = make_dedup_key(event_type, payload, recipient_user_id)
            try:
                if self.notification_store.should_dedup(
                    dedup_key,
                    recipient_user_id,
                    event_type,
                    summary,
                ):
                    logger.info(
                        "[NOTIFY] deduplicated", extra={
                            "event": "notification_deduplicated",
                            "event_type": event_type,
                            "recipient_user_id": recipient_user_id,
                        }
                    )
                    continue
                if frequency == "digest":
                    self.notification_store.enqueue_digest(
                        recipient_user_id, event_type, summary
                    )
                    logger.info(
                        "[NOTIFY] queued digest", extra={
                            "event": "notification_digest_queued",
                            "event_type": event_type,
                            "recipient_user_id": recipient_user_id,
                        }
                    )
                    continue
                result = self.gmail_sender.send_email(
                    recipient_user_id, subject, message
                )
                if result.get("success"):
                    self.notification_store.mark_sent(dedup_key)
                else:
                    logger.info(
                        "[NOTIFY] Gmail recipient skipped: %s", result.get("error", "delivery_failed"), extra={
                            "event": "notification_recipient_skipped",
                            "event_type": event_type,
                            "recipient_user_id": recipient_user_id,
                            "reason": result.get("error", "delivery_failed"),
                        }
                    )
                results.append({**result, "channel": "Gmail", "recipient_user_id": recipient_user_id})
            except Exception:
                # A recipient-specific failure must never affect the producer.
                logger.warning(
                    "[NOTIFY] Gmail recipient skipped", extra={
                        "event": "notification_recipient_skipped",
                        "event_type": event_type,
                        "recipient_user_id": recipient_user_id,
                        "reason": "dispatch_failed",
                    }
                )

    def send_pending_digests(self) -> list[dict]:
        """Send one combined SUSPICIOUS digest per user and mark delivered rows."""
        if self.gmail_sender is None or self.notification_store is None:
            return []
        rows = self.notification_store.pending_digest()
        grouped: dict[int, list[Any]] = {}
        for row in rows:
            grouped.setdefault(int(row["recipient_user_id"]), []).append(row)
        results: list[dict] = []
        for user_id, user_rows in grouped.items():
            lines = ["[CTI DIGEST] SUSPICIOUS notifications"]
            for row in user_rows:
                try:
                    item = json.loads(row["payload_summary"])
                except (TypeError, ValueError):
                    item = {}
                lines.append(json.dumps(item, sort_keys=True))
            result = self.gmail_sender.send_email(
                user_id, "[CTI DIGEST] SUSPICIOUS notifications", "\n".join(lines)
            )
            results.append({**result, "channel": "Gmail", "recipient_user_id": user_id})
            if result.get("success"):
                self.notification_store.mark_digest_sent([int(row["id"]) for row in user_rows])
        return results

    @staticmethod
    def _format_message(event_type: str, payload: dict) -> Tuple[str, str]:
        """Build a short ``(subject, message)`` pair for *event_type*."""
        payload = payload or {}

        if event_type == "verdict_alert":
            subject = "[CTI ALERT]"
            message = (
                f"[CTI ALERT] {payload.get('verdict', 'UNKNOWN')} verdict for "
                f"{payload.get('ioc', 'unknown IOC')} - session {payload.get('session_id', '')}"
            )
        elif event_type == "approval_required":
            subject = "[APPROVAL NEEDED]"
            message = (
                f"[APPROVAL NEEDED] {payload.get('tool', '')} on "
                f"{payload.get('session_id', '')}: {payload.get('description', '')}"
            )
        elif event_type == "action_executed":
            subject = "[ACTION EXECUTED]"
            message = (
                f"[ACTION EXECUTED] {payload.get('tool', '')} completed on "
                f"{payload.get('session_id', '')} - status: {payload.get('status', 'unknown')}"
            )
        else:
            subject = f"[{event_type}]"
            message = str(payload)

        return subject, message


