"""Per-user Gmail delivery adapter for Phase 5 notifications."""

from __future__ import annotations

import base64
import logging
from email.mime.text import MIMEText
from typing import Any, Callable

from googleapiclient.discovery import build

from .gmail_oauth import GmailOAuthService

logger = logging.getLogger(__name__)


class GmailSender:
    """Send one message through the linked user's Gmail account."""

    def __init__(
        self,
        service: Any | None = None,
        db_path: str | None = None,
        build_client: Callable[..., Any] | None = None,
    ):
        self.service = service or GmailOAuthService(db_path=db_path)
        self._build_client = build_client or build

    def send_email(self, user_id: int, subject: str, body: str) -> dict:
        """Deliver without raising or logging credentials/authorization data."""
        try:
            status = self.service.get_status(int(user_id))
            if not status.get("linked"):
                return {"success": False, "error": "gmail_not_linked"}
            if status.get("revoked"):
                return {"success": False, "error": "gmail_revoked"}
            credentials = self.service.refresh_access_token(int(user_id))
            message = MIMEText(body or "", "plain", "utf-8")
            message["To"] = str(status.get("google_email") or "")
            message["Subject"] = subject or ""
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii").rstrip("=")
            client = self._build_client("gmail", "v1", credentials=credentials)
            client.users().messages().send(userId="me", body={"raw": raw}).execute()
            return {"success": True}
        except Exception:
            # Deliberately use a stable error code. Google/transport exceptions
            # can contain sensitive request material and must not enter logs.
            logger.warning(
                "[NOTIFY] Gmail delivery failed", extra={"event": "gmail_delivery_failed", "user_id": int(user_id)}
            )
            return {"success": False, "error": "gmail_delivery_failed"}
