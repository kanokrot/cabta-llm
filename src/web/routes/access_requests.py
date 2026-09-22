"""Public access requests and admin review endpoints."""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .. import auth as auth_core
from .. import security
from . import admin as admin_routes


REQUESTABLE_ROLES = (
    "Team Lead",
)
ACCESS_REQUEST_RATE_LIMIT_IDENTIFIER = "public-access-request"
ACCESS_REQUEST_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

router = APIRouter()
access_request_rate_limiter = security.LoginRateLimiter(
    max_attempts=int(os.getenv("ACCESS_REQUEST_MAX_ATTEMPTS", "5")),
    window_seconds=int(
        os.getenv("ACCESS_REQUEST_WINDOW_SECONDS", str(15 * 60))
    ),
)


def _connect() -> sqlite3.Connection:
    db_path = Path(os.getenv(auth_core.AUTH_DB_ENV, "src/db/auth.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    return connection


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    return bool(ACCESS_REQUEST_EMAIL_RE.fullmatch(normalize_email(email)))


def check_rate_limit(client_ip: str) -> tuple[bool, int]:
    """Record one submission and return ``(limited, retry_after_seconds)``."""
    if access_request_rate_limiter.is_limited(
        ACCESS_REQUEST_RATE_LIMIT_IDENTIFIER, client_ip
    ):
        return (
            True,
            access_request_rate_limiter.retry_after(
                ACCESS_REQUEST_RATE_LIMIT_IDENTIFIER, client_ip
            ),
        )
    access_request_rate_limiter.record_failure(
        ACCESS_REQUEST_RATE_LIMIT_IDENTIFIER, client_ip
    )
    return False, 0


def create_access_request(
    *, name: str, email: str, requested_role: str, reason: str
) -> dict[str, Any]:
    normalized_email = normalize_email(email)
    if requested_role not in REQUESTABLE_ROLES:
        raise ValueError("Unsupported requested role")

    try:
        with _connect() as connection:
            existing = connection.execute(
                """
                SELECT id FROM access_requests
                WHERE lower(email) = lower(?) AND status = 'pending'
                """,
                (normalized_email,),
            ).fetchone()
            if existing is not None:
                raise ValueError(
                    "A pending access request already exists for this email"
                )
            cursor = connection.execute(
                """
                INSERT INTO access_requests
                    (name, email, requested_role, reason)
                VALUES (?, ?, ?, ?)
                """,
                (name.strip(), normalized_email, requested_role, reason.strip()),
            )
            row = connection.execute(
                """
                SELECT id, name, email, requested_role, reason, status,
                       created_at, decided_at, decided_by
                FROM access_requests
                WHERE id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()
            return dict(row)
    except sqlite3.IntegrityError:
        raise ValueError("A pending access request already exists for this email")


def list_pending_access_requests() -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT id, name, email, requested_role, reason, status,
                   created_at, decided_at, decided_by
            FROM access_requests
            WHERE status = 'pending'
            ORDER BY created_at ASC, id ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_pending_access_request(request_id: int) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            """
            SELECT id, name, email, requested_role, reason, status,
                   created_at, decided_at, decided_by
            FROM access_requests
            WHERE id = ? AND status = 'pending'
            """,
            (request_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def decide_access_request(
    request_id: int, *, decision: str, decided_by: int
) -> bool:
    if decision not in {"approved", "rejected"}:
        raise ValueError("Unsupported access request decision")
    with _connect() as connection:
        cursor = connection.execute(
            """
            UPDATE access_requests
            SET status = ?, decided_at = CURRENT_TIMESTAMP, decided_by = ?
            WHERE id = ? AND status = 'pending'
            """,
            (decision, int(decided_by), request_id),
        )
        return cursor.rowcount == 1


@router.get("/access-requests")
def list_access_requests(
    _admin_user: dict = Depends(auth_core.require_role("admin")),
) -> dict[str, Any]:
    return {"requests": list_pending_access_requests()}


@router.post("/access-requests/{request_id}/approve")
def approve_access_request(
    request_id: int,
    request: Request,
    admin_user: dict = Depends(auth_core.require_role("admin")),
) -> dict[str, Any]:
    access_request = get_pending_access_request(request_id)
    if access_request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending access request not found",
        )

    # Call the existing admin invitation endpoint function so token creation,
    # email delivery, and its error handling remain in one place.
    invitation = admin_routes.invite_user(
        admin_routes.InviteUserRequest(
            email=access_request["email"],
            role=access_request["requested_role"],
        ),
        request,
        admin_user,
    )
    if not decide_access_request(
        request_id, decision="approved", decided_by=int(admin_user["id"])
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Access request was already decided",
        )
    return {
        "request_id": request_id,
        "status": "approved",
        "invitation": invitation,
    }


@router.post("/access-requests/{request_id}/reject")
def reject_access_request(
    request_id: int,
    admin_user: dict = Depends(auth_core.require_role("admin")),
) -> dict[str, Any]:
    if not decide_access_request(
        request_id, decision="rejected", decided_by=int(admin_user["id"])
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending access request not found",
        )
    return {"request_id": request_id, "status": "rejected"}
