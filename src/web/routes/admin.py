"""Admin-only invitation endpoint for Phase 1.5."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from src.integrations.notifications import EmailChannel

from ..auth import (
    INVITE_TOKEN_TTL_SECONDS,
    VALID_ROLES,
    create_invite_token,
    require_role,
)


router = APIRouter()


class InviteUserRequest(BaseModel):
    email: str = Field(min_length=1)
    role: str = Field(min_length=1)


@router.post("/users/invite", status_code=status.HTTP_202_ACCEPTED)
def invite_user(
    payload: InviteUserRequest,
    request: Request,
    admin_user: dict = Depends(require_role("admin")),
) -> dict:
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Unsupported role")

    config = getattr(request.app.state, "config", {}) or {}
    email_cfg = dict(
        (config.get("notifications", {}) or {}).get("email", {}) or {}
    )
    if not email_cfg.get("enabled"):
        raise HTTPException(
            status_code=503,
            detail="Invitation email is not configured",
        )

    normalized_email = payload.email.strip().lower()
    try:
        token = create_invite_token(
            normalized_email, payload.role, admin_user["id"]
        )
    except ValueError as exc:
        detail = str(exc)
        code = 400 if detail == "Invalid email" else 409
        raise HTTPException(status_code=code, detail=detail) from exc

    email_cfg["to_addrs"] = [normalized_email]
    result = EmailChannel(email_cfg).send(
        "[CTI INVITE] Complete your account registration",
        "An administrator invited you to the CTI system.\n\n"
        f"Invite token: {token}\n"
        "Accept it with POST /api/auth/accept-invite using the token, "
        "a username, and a password.\n"
        f"This invite expires in {INVITE_TOKEN_TTL_SECONDS // 3600} hours.",
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Invitation email could not be sent",
        )

    return {
        "email": normalized_email,
        "role": payload.role,
        "expires_at": int(time.time()) + INVITE_TOKEN_TTL_SECONDS,
    }
