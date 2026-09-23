"""HTTP endpoints for Phase 1 Auth core."""

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, model_validator

from ..auth import (
    ACCESS_TOKEN_TTL_SECONDS,
    authenticate_user,
    consume_invite_token,
    create_access_token,
    get_access_token,
    get_current_user,
    oauth2_scheme,
    public_user,
    revoke_token,
)
from ..security import (
    COOKIE_SAMESITE,
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    cookie_secure,
    login_rate_limiter,
)
from ..page_auth import ROLE_DEFAULT_LANDING


router = APIRouter()


class LoginRequest(BaseModel):
    email: str | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1, max_length=64)
    password: str = Field(min_length=1)

    @model_validator(mode="after")
    def require_identifier(self) -> "LoginRequest":
        if not self.email and not self.username:
            raise ValueError("email or username is required")
        return self


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=1)
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=72)


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    identifier = (payload.username or payload.email or "").strip()
    client_ip = request.client.host if request.client else "unknown"

    if login_rate_limiter.is_limited(identifier, client_ip):
        retry_after = login_rate_limiter.retry_after(identifier, client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = authenticate_user(identifier, payload.password)
    if user is None:
        login_rate_limiter.record_failure(identifier, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    login_rate_limiter.clear(identifier, client_ip)
    access_token = create_access_token(user)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        access_token,
        max_age=ACCESS_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=cookie_secure(),
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        secrets.token_urlsafe(32),
        max_age=ACCESS_TOKEN_TTL_SECONDS,
        httponly=False,
        secure=cookie_secure(),
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    return {
        "authenticated": True,
        "user": public_user(user),
        "default_redirect": ROLE_DEFAULT_LANDING.get(user["role"], "/dashboard"),
    }


@router.post("/accept-invite")
def accept_invite(payload: AcceptInviteRequest) -> dict:
    try:
        user = consume_invite_token(
            payload.token, payload.username, payload.password
        )
    except ValueError as exc:
        detail = str(exc)
        if detail == "Invite token expired":
            code = status.HTTP_410_GONE
        elif detail in {
            "Username is already taken",
            "Invite has already been accepted",
            "Invite token already used",
        }:
            code = status.HTTP_409_CONFLICT
        else:
            code = status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=code, detail=detail) from exc
    return {"user": public_user(user)}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    token: str = Depends(get_access_token),
    current_user: dict = Depends(get_current_user),
) -> Response:
    del current_user
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    revoke_token(token)
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=cookie_secure(),
        httponly=True,
        samesite=COOKIE_SAMESITE,
    )
    response.delete_cookie(
        CSRF_COOKIE_NAME,
        path="/",
        secure=cookie_secure(),
        httponly=False,
        samesite=COOKIE_SAMESITE,
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
