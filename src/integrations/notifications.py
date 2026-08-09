"""
Notification integrations - Email (SMTP) and LINE Messaging API.

Provides a small ``NotificationManager`` that fans out alert-style events
(high-severity verdicts, approval checkpoints, executed actions) to whatever
channels are enabled in ``config['notifications']``. Designed to never raise:
failures are logged and swallowed so a broken/unconfigured channel can't take
down the agent loop or a playbook run.
"""

import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, List, Tuple

import requests

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

        if not self.enabled:
            return

        email_cfg = notif_cfg.get("email", {}) or {}
        if email_cfg.get("enabled"):
            self.channels.append(EmailChannel(email_cfg))

        line_cfg = notif_cfg.get("line", {}) or {}
        if line_cfg.get("enabled"):
            self.channels.append(LineChannel(line_cfg))

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

        if not self.channels:
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


