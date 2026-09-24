"""Password hashing and short-lived credential encryption."""

from __future__ import annotations

import json
import os
from typing import Any

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken, MultiFernet


_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Application passwords must contain at least 12 characters")
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except Exception:
        return False


class CredentialCipher:
    """Encrypt with the first key and decrypt with any configured rotation key."""

    def __init__(self, keys: list[bytes]):
        if not keys:
            raise ValueError("At least one credential encryption key is required")
        self._cipher = MultiFernet([Fernet(key) for key in keys])

    @classmethod
    def from_env(cls) -> "CredentialCipher":
        raw = os.getenv("SENTINEL_CREDENTIAL_KEYS", "")
        keys = [value.strip().encode("ascii") for value in raw.split(",") if value.strip()]
        if not keys:
            raise ValueError(
                "SENTINEL_CREDENTIAL_KEYS is required; generate a Fernet key and keep it outside the database"
            )
        return cls(keys)

    def encrypt(self, payload: dict[str, Any]) -> bytes:
        return self._cipher.encrypt(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )

    def decrypt(self, token: bytes) -> dict[str, Any]:
        try:
            value = json.loads(self._cipher.decrypt(token).decode("utf-8"))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Stored scan credentials could not be decrypted") from exc
        if not isinstance(value, dict):
            raise ValueError("Stored scan credentials have an invalid shape")
        return value
