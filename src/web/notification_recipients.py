"""Role-scoped notification recipient lookup without exposing OAuth secrets."""

from __future__ import annotations

import sqlite3
from typing import Any

from .auth import VALID_ROLES, _connect


def get_active_users_with_gmail(role: str) -> list[dict[str, Any]]:
    """Return active users for *role* and whether each has Gmail linked.

    Only a user id, delivery email, and boolean link status leave this helper;
    OAuth token ciphertext and token metadata are deliberately not selected.
    """
    if role not in VALID_ROLES:
        raise ValueError("Unsupported role")
    try:
        with _connect() as connection:
            rows = connection.execute(
                "SELECT u.id, t.google_email, t.user_id AS gmail_user_id "
                "FROM users u LEFT JOIN user_gmail_tokens t ON t.user_id = u.id "
                "AND t.revoked_at IS NULL "
                "WHERE u.role = ? AND u.is_active = 1 ORDER BY u.id",
                (role,),
            ).fetchall()
    except sqlite3.OperationalError:
        # A partially provisioned local installation has no recipients yet.
        return []
    return [
        {
            "user_id": int(row["id"]),
            "email": row["google_email"],
            "gmail_linked": row["gmail_user_id"] is not None,
        }
        for row in rows
    ]
