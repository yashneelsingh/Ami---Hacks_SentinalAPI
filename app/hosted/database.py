"""Engine lifecycle, health checks, and metadata-safe query observability."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.structured_logging import configure_logging, log_event

from .config import HostedDatabaseSettings
from .models import Base


logger = configure_logging()
REQUIRED_TABLES = {
    "organizations",
    "application_users",
    "application_sessions",
    "scans",
    "tested_endpoints",
    "findings",
    "scan_credentials",
    "audit_events",
    "alembic_version",
}
REQUIRED_INDEXES = {
    "application_users": {"ix_application_users_org_active"},
    "application_sessions": {
        "ix_application_sessions_user_expires",
        "ix_application_sessions_expires_at",
    },
    "scans": {"ix_scans_org_status_created", "ix_scans_status_lease", "ix_scans_expires_at"},
    "tested_endpoints": {"ix_tested_endpoints_scan_outcome"},
    "findings": {"ix_findings_scan_severity"},
    "scan_credentials": {"ix_scan_credentials_expires_at"},
    "audit_events": {"ix_audit_events_org_created", "ix_audit_events_scan_created"},
}


def create_hosted_engine(
    settings: HostedDatabaseSettings,
    *,
    memory_test_database: bool = False,
) -> Engine:
    kwargs: dict = {"pool_pre_ping": True}
    if settings.database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if memory_test_database:
            kwargs["poolclass"] = StaticPool
    else:
        kwargs.update(
            pool_size=settings.pool_size,
            max_overflow=settings.max_overflow,
            pool_timeout=settings.pool_timeout_seconds,
        )
    engine = create_engine(settings.database_url, **kwargs)
    _install_connection_safety(engine)
    _install_slow_query_logging(engine, settings.slow_query_ms)
    return engine


def _install_connection_safety(engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA busy_timeout = 10000")
        cursor.close()


def _install_slow_query_logging(engine: Engine, threshold_ms: int) -> None:
    @event.listens_for(engine, "before_cursor_execute")
    def _before(_conn: Connection, _cursor, _statement, _parameters, context, _executemany) -> None:
        context._sentinel_started_at = time.monotonic()

    @event.listens_for(engine, "after_cursor_execute")
    def _after(_conn: Connection, _cursor, statement, _parameters, context, _executemany) -> None:
        elapsed_ms = (time.monotonic() - context._sentinel_started_at) * 1000
        if elapsed_ms >= threshold_ms:
            operation = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else "UNKNOWN"
            log_event(
                logger,
                "hosted_database_slow_query",
                level=logging.WARNING,
                operation=operation,
                elapsed_ms=round(elapsed_ms, 2),
            )


def hosted_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@contextmanager
def hosted_session(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def health_check(engine: Engine) -> dict[str, str]:
    started = time.monotonic()
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    result = {
        "status": "ok",
        "dialect": engine.dialect.name,
        "latency_ms": f"{(time.monotonic() - started) * 1000:.2f}",
    }
    for name, attribute in (
        ("pool_size", "size"),
        ("pool_checked_out", "checkedout"),
        ("pool_overflow", "overflow"),
    ):
        metric = getattr(engine.pool, attribute, None)
        if callable(metric):
            value = metric()
            result[name] = str(max(0, value) if name == "pool_overflow" else value)
    return result


def verify_schema_integrity(engine: Engine) -> None:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    missing = REQUIRED_TABLES - tables
    if missing:
        raise RuntimeError(
            "Hosted database schema is incomplete; run `alembic upgrade head`. "
            f"Missing: {', '.join(sorted(missing))}"
        )
    for table, expected_indexes in REQUIRED_INDEXES.items():
        indexes = {entry["name"] for entry in inspector.get_indexes(table)}
        missing_indexes = expected_indexes - indexes
        if missing_indexes:
            raise RuntimeError(
                "Hosted database indexes are incomplete; run `alembic upgrade head`. "
                f"Missing on {table}: {', '.join(sorted(missing_indexes))}"
            )


def create_test_schema(engine: Engine) -> None:
    """Tests only; deployed environments must use Alembic migrations."""
    Base.metadata.create_all(engine)
