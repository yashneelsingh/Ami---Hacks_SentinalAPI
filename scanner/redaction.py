"""Credential redaction shared by scanner output and reproductions."""

from __future__ import annotations

import re
from typing import Any, Iterable


REDACTED = "<REDACTED>"
_SENSITIVE_KEYS = {
    "authorization",
    "access_token",
    "accesstoken",
    "password",
    "refresh_token",
    "refreshtoken",
    "token",
}
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[^\s\"']+")


def redact_text(value: object, secrets: Iterable[str] = ()) -> str:
    """Redact bearer credentials and explicitly supplied secret values."""
    text = str(value)
    text = _BEARER_PATTERN.sub(r"\1<REDACTED>", text)
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), REDACTED)
    return text


def redact_value(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Return a JSON-compatible copy with credential-bearing values removed."""
    secret_values = tuple(str(secret) for secret in secrets if secret)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, child in value.items():
            normalized = "".join(character for character in str(key).lower() if character.isalnum() or character == "_")
            if normalized in _SENSITIVE_KEYS or normalized.endswith("token"):
                if normalized == "authorization" and isinstance(child, str) and child.lower().startswith("bearer "):
                    redacted[key] = "Bearer <REDACTED>"
                else:
                    redacted[key] = REDACTED
            else:
                redacted[key] = redact_value(child, secret_values)
        return redacted
    if isinstance(value, list):
        return [redact_value(child, secret_values) for child in value]
    if isinstance(value, tuple):
        return tuple(redact_value(child, secret_values) for child in value)
    if isinstance(value, str):
        return redact_text(value, secret_values)
    return value
