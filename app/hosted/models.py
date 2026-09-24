"""SQLAlchemy models for hosted, organization-isolated scan persistence."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


SCAN_STATUSES = (
    "queued",
    "validating",
    "running",
    "completed",
    "failed",
    "cancelled",
    "expired",
)
TERMINAL_STATUSES = {"completed", "failed", "cancelled", "expired"}


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    users: Mapped[list["ApplicationUser"]] = relationship(back_populates="organization")
    scans: Mapped[list["Scan"]] = relationship(back_populates="organization")


class ApplicationUser(Base):
    __tablename__ = "application_users"
    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="uq_application_users_org_email"),
        Index("ix_application_users_org_active", "organization_id", "is_active"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="member", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="users")
    scans: Mapped[list["Scan"]] = relationship(back_populates="creator")
    sessions: Mapped[list["ApplicationSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class ApplicationSession(Base):
    __tablename__ = "application_sessions"
    __table_args__ = (
        Index("ix_application_sessions_user_expires", "user_id", "expires_at"),
        Index("ix_application_sessions_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("application_users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[ApplicationUser] = relationship(back_populates="sessions")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("request_budget > 0", name="ck_scans_positive_request_budget"),
        CheckConstraint("request_count >= 0", name="ck_scans_nonnegative_request_count"),
        CheckConstraint("request_count <= request_budget", name="ck_scans_request_budget"),
        CheckConstraint(
            "status IN ('queued','validating','running','completed','failed','cancelled','expired')",
            name="ck_scans_status",
        ),
        Index("ix_scans_org_status_created", "organization_id", "status", "created_at"),
        Index("ix_scans_status_lease", "status", "lease_expires_at"),
        Index("ix_scans_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    created_by_id: Mapped[str] = mapped_column(
        ForeignKey("application_users.id", ondelete="RESTRICT"), nullable=False
    )
    target_identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_budget: Mapped[int] = mapped_column(Integer, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result: Mapped[str | None] = mapped_column(String(32))
    result_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    failure_code: Mapped[str | None] = mapped_column(String(64))
    worker_id: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="scans")
    creator: Mapped[ApplicationUser] = relationship(back_populates="scans")
    endpoints: Mapped[list["TestedEndpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    credential: Mapped["ScanCredential | None"] = relationship(
        back_populates="scan", cascade="all, delete-orphan", uselist=False
    )


class TestedEndpoint(Base):
    __tablename__ = "tested_endpoints"
    __table_args__ = (
        UniqueConstraint("scan_id", "method", "endpoint", name="uq_tested_endpoints_scan_route"),
        CheckConstraint(
            "outcome IN ('pass','fail','inconclusive','error')",
            name="ck_tested_endpoints_outcome",
        ),
        Index("ix_tested_endpoints_scan_outcome", "scan_id", "outcome"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    method: Mapped[str] = mapped_column(String(12), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    safe_details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="endpoints")


class FindingRecord(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    method: Mapped[str] = mapped_column(String(12), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    expected_result: Mapped[str] = mapped_column(Text, nullable=False)
    actual_result: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class ScanCredential(Base):
    __tablename__ = "scan_credentials"
    __table_args__ = (Index("ix_scan_credentials_expires_at", "expires_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    encrypted_payload: Mapped[bytes] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="credential")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_created", "organization_id", "created_at"),
        Index("ix_audit_events_scan_created", "scan_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("application_users.id", ondelete="SET NULL")
    )
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
