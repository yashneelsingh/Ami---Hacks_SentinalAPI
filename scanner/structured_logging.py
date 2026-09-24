"""Small JSON logging layer with credential-safe structured fields."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, TextIO

from .redaction import redact_text, redact_value


LOGGER_NAME = "sentinelapi"


class JsonFormatter(logging.Formatter):
    """Render one JSON object per line and redact all structured values."""

    def format(self, record: logging.LogRecord) -> str:
        secrets = getattr(record, "redaction_secrets", ())
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "event": redact_text(record.getMessage(), secrets),
        }
        fields = getattr(record, "event_fields", None)
        if isinstance(fields, dict):
            payload.update(redact_value(fields, secrets))
        if record.exc_info:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def configure_logging(stream: TextIO | None = None) -> logging.Logger:
    """Configure the SentinelAPI logger once and return it."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    return logger


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    secrets: Iterable[str] = (),
    **fields: Any,
) -> None:
    """Emit a named event whose structured fields are redacted before output."""
    secret_values = tuple(str(secret) for secret in secrets if secret)
    logger.log(
        level,
        event,
        extra={
            "event_fields": redact_value(fields, secret_values),
            "redaction_secrets": secret_values,
        },
    )

