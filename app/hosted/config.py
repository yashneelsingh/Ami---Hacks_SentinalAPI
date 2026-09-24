"""Environment-specific settings for the hosted persistence layer."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent
ENVIRONMENTS = {"development", "test", "staging", "production"}


@dataclass(frozen=True)
class HostedDatabaseSettings:
    environment: str
    database_url: str
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout_seconds: int = 10
    slow_query_ms: int = 250

    @classmethod
    def from_env(cls) -> "HostedDatabaseSettings":
        environment = os.getenv("SENTINEL_ENV", "development").strip().lower()
        if environment not in ENVIRONMENTS:
            raise ValueError(f"SENTINEL_ENV must be one of: {', '.join(sorted(ENVIRONMENTS))}")

        configured_url = os.getenv("SENTINEL_DATABASE_URL", "").strip()
        if environment in {"staging", "production"}:
            if not configured_url:
                raise ValueError("SENTINEL_DATABASE_URL is required for staging and production")
            if not configured_url.startswith(("postgresql://", "postgresql+psycopg://")):
                raise ValueError("Staging and production require a PostgreSQL database URL")
        database_url = configured_url or f"sqlite:///{(ROOT / 'data' / f'sentinel_hosted_{environment}.db').as_posix()}"

        return cls(
            environment=environment,
            database_url=database_url,
            pool_size=_positive_int("SENTINEL_DB_POOL_SIZE", 5),
            max_overflow=_nonnegative_int("SENTINEL_DB_MAX_OVERFLOW", 10),
            pool_timeout_seconds=_positive_int("SENTINEL_DB_POOL_TIMEOUT_SECONDS", 10),
            slow_query_ms=_positive_int("SENTINEL_DB_SLOW_QUERY_MS", 250),
        )


def _positive_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _nonnegative_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value < 0:
        raise ValueError(f"{name} must not be negative")
    return value
