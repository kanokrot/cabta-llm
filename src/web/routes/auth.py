"""HTTP endpoints for Phase 1 Auth core."""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from ..auth import (
    authenticate_user,
    consume_invite_token,
    create_access_token,
    get_current_user,
    oauth2_scheme,
    public_user,
    revoke_token,
)


router = APIRouter()


class LoginRequest(BaseModel):
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=1)
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=72)


@router.post("/login")
def login(payload: LoginRequest) -> dict:
    user = authenticate_user(payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "user": public_user(user),
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
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(get_current_user),
) -> Response:
    del current_user
    revoke_token(token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
