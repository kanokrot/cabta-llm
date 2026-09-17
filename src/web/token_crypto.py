"""Fail-closed encryption for locally stored OAuth refresh tokens."""

from __future__ import annotations

import json
import os
from typing import Iterable

from cryptography.fernet import Fernet, MultiFernet


KEY_ENV = "GMAIL_TOKEN_ENCRYPTION_KEY"


def _parse_keys(value: str) -> list[bytes]:
    raw = value.strip()
    if not raw:
        raise RuntimeError(f"{KEY_ENV} must contain at least one Fernet key")
    try:
        parsed = json.loads(raw) if raw.startswith("[") else [item.strip() for item in raw.split(",")]
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{KEY_ENV} must be a comma-separated or JSON list of Fernet keys") from exc
    if not isinstance(parsed, list) or not parsed:
        raise RuntimeError(f"{KEY_ENV} must contain at least one Fernet key")
    keys: list[bytes] = []
    for item in parsed:
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(f"{KEY_ENV} contains an invalid key entry")
        keys.append(item.strip().encode("ascii"))
    try:
        for key in keys:
            Fernet(key)
    except Exception as exc:
        raise RuntimeError(f"{KEY_ENV} contains an invalid Fernet key") from exc
    return keys


class TokenCipher:
    """Multi-key Fernet cipher; index zero is always the encryption key."""

    def __init__(self, keys: Iterable[bytes | str]):
        normalized = [key.encode("ascii") if isinstance(key, str) else key for key in keys]
        if not normalized:
            raise RuntimeError(f"{KEY_ENV} must contain at least one Fernet key")
        self._keys = tuple(normalized)
        try:
            self._cipher = MultiFernet([Fernet(key) for key in self._keys])
        except Exception as exc:
            raise RuntimeError(f"{KEY_ENV} contains an invalid Fernet key") from exc

    @classmethod
    def from_environment(cls) -> "TokenCipher":
        value = os.getenv(KEY_ENV)
        if not value:
            raise RuntimeError(
                f"{KEY_ENV} must be set; refusing to store or decrypt Gmail tokens"
            )
        return cls(_parse_keys(value))

    @property
    def key_version(self) -> int:
        return 1

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("refresh token must be a non-empty string")
        return self._cipher.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        return self._cipher.decrypt(ciphertext.encode("ascii")).decode("utf-8")
