"""Authentication primitives for Phase 1 Auth core."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext


AUTH_DB_ENV = "AUTH_DB_PATH"
JWT_SECRET_ENV = "AUTH_JWT_SECRET"
ACCESS_TOKEN_TTL_SECONDS = 60 * 60
INVITE_TOKEN_TTL_SECONDS = 48 * 60 * 60
VALID_ROLES = frozenset(
    {
        "SOC Analyst Tier 1-2",
        "Incident Responder",
        "Threat Hunter",
        "admin",
    }
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def _connect() -> sqlite3.Connection:
    db_path = Path(os.getenv(AUTH_DB_ENV, "src/db/auth.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    return connection


def _jwt_secret() -> bytes:
    secret = os.getenv(JWT_SECRET_ENV)
    if not secret:
        raise RuntimeError(f"{JWT_SECRET_ENV} must be configured")
    return secret.encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode_jwt(payload: Dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(_jwt_secret(), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64encode(signature)}"


def _decode_jwt(token: str) -> Dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected_signature = hmac.new(
            _jwt_secret(), signing_input, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64decode(encoded_signature), expected_signature):
            raise ValueError("invalid signature")
        header = json.loads(_b64decode(encoded_header))
        payload = json.loads(_b64decode(encoded_payload))
        if header.get("alg") != "HS256" or int(payload["exp"]) <= int(time.time()):
            raise ValueError("expired or invalid token")
        return payload
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("invalid access token") from exc


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    with _connect() as connection:
        row = connection.execute(
            "SELECT id, email, username, password_hash, role, is_active "
            "FROM users WHERE lower(email) = lower(?)",
            (email.strip(),),
        ).fetchone()

    if row is None or not row["is_active"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return dict(row)


def create_access_token(user: Dict[str, Any]) -> str:
    now = int(time.time())
    expires_at = now + ACCESS_TOKEN_TTL_SECONDS
    jti = secrets.token_urlsafe(16)
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": now,
        "exp": expires_at,
        "jti": jti,
    }
    token = _encode_jwt(payload)

    with _connect() as connection:
        connection.execute(
            "INSERT INTO auth_sessions "
            "(jti, user_id, expires_at) VALUES (?, ?, ?)",
            (jti, int(user["id"]), expires_at),
        )
        connection.commit()
    return token


def _session_is_active(connection: sqlite3.Connection, jti: str) -> bool:
    row = connection.execute(
        "SELECT expires_at, revoked_at FROM auth_sessions WHERE jti = ?",
        (jti,),
    ).fetchone()
    return bool(
        row
        and row["revoked_at"] is None
        and int(row["expires_at"]) > int(time.time())
    )


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = _decode_jwt(token)
        user_id = int(payload["sub"])
        jti = str(payload["jti"])
    except (ValueError, KeyError, TypeError):
        raise credentials_error

    with _connect() as connection:
        if not _session_is_active(connection, jti):
            raise credentials_error
        row = connection.execute(
            "SELECT id, email, username, role, is_active FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if row is None or not row["is_active"]:
        raise credentials_error
    return dict(row)


def _normalize_roles(roles: str | Sequence[str]) -> frozenset[str]:
    allowed_roles = frozenset((roles,) if isinstance(roles, str) else roles)
    if not allowed_roles or not allowed_roles.issubset(VALID_ROLES):
        raise ValueError("Unsupported role")
    return allowed_roles


def authorize_role(
    current_user: Dict[str, Any], roles: str | Sequence[str]
) -> None:
    if current_user.get("role") not in _normalize_roles(roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )


def require_role(roles: str | Sequence[str]):
    allowed_roles = _normalize_roles(roles)

    def dependency(current_user: Dict[str, Any] = Depends(get_current_user)):
        authorize_role(current_user, allowed_roles)
        return current_user

    return dependency


def create_invite_token(
    email: str,
    role: str,
    invited_by: int,
    ttl_seconds: int = INVITE_TOKEN_TTL_SECONDS,
) -> str:
    normalized_email = email.strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"Unsupported role: {role}")
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("Invalid email")

    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + ttl_seconds
    placeholder_hash = hash_password(secrets.token_urlsafe(32))

    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT id FROM users WHERE lower(email) = lower(?)",
            (normalized_email,),
        ).fetchone()
        if existing is not None:
            raise ValueError("Email is already registered or invited")

        connection.execute(
            "INSERT INTO users "
            "(email, password_hash, role, is_active) VALUES (?, ?, ?, 0)",
            (normalized_email, placeholder_hash, role),
        )
        connection.execute(
            "INSERT INTO invite_tokens "
            "(token, email, role, invited_by, expires_at) VALUES (?, ?, ?, ?, ?)",
            (token, normalized_email, role, int(invited_by), expires_at),
        )
        connection.commit()
    return token


def consume_invite_token(token: str, username: str, password: str) -> Dict[str, Any]:
    token = token.strip()
    username = username.strip()
    if not token:
        raise ValueError("Invalid invite token")
    if not username:
        raise ValueError("Username is required")

    password_hash = hash_password(password)
    now = int(time.time())

    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        invite = connection.execute(
            "SELECT token, email, role, expires_at, used_at "
            "FROM invite_tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if invite is None:
            raise ValueError("Invalid invite token")
        if invite["used_at"] is not None:
            raise ValueError("Invite token already used")
        if int(invite["expires_at"]) <= now:
            raise ValueError("Invite token expired")

        user = connection.execute(
            "SELECT id, email, username, is_active FROM users "
            "WHERE lower(email) = lower(?)",
            (invite["email"],),
        ).fetchone()
        if user is None or user["is_active"]:
            raise ValueError("Invite has already been accepted")

        duplicate_username = connection.execute(
            "SELECT id FROM users WHERE lower(username) = lower(?) AND id != ?",
            (username, user["id"]),
        ).fetchone()
        if duplicate_username is not None:
            raise ValueError("Username is already taken")

        connection.execute(
            "UPDATE users SET username = ?, password_hash = ?, "
            "role = ?, is_active = 1 WHERE id = ?",
            (username, password_hash, invite["role"], user["id"]),
        )
        connection.execute(
            "UPDATE invite_tokens SET used_at = ? WHERE token = ?",
            (now, token),
        )
        activated = connection.execute(
            "SELECT id, email, username, role, is_active FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        connection.commit()
    return dict(activated)


def revoke_token(token: str) -> None:
    payload = _decode_jwt(token)
    with _connect() as connection:
        connection.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE jti = ?",
            (int(time.time()), str(payload["jti"])),
        )
        connection.commit()


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "username": user.get("username"),
        "role": user["role"],
    }
