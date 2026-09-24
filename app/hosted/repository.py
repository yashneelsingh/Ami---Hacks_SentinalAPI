"""Tenant-scoped persistence and atomic hosted scan-job operations."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from scanner.redaction import redact_value

from .models import (
    ApplicationUser,
    ApplicationSession,
    AuditEvent,
    FindingRecord,
    Organization,
    Scan,
    ScanCredential,
    TERMINAL_STATUSES,
    TestedEndpoint,
    utcnow,
)
from .security import CredentialCipher, hash_password, verify_password


ALLOWED_TRANSITIONS = {
    "queued": {"validating", "cancelled", "expired"},
    "validating": {"running", "failed", "cancelled", "expired"},
    "running": {"completed", "failed", "cancelled", "expired"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
    "expired": set(),
}


class NotFoundError(LookupError):
    """The record does not exist in the caller's organization."""


class InvalidStateError(RuntimeError):
    """The requested job transition violates the scan state machine."""


class HostedRepository:
    def __init__(self, sessions: sessionmaker[Session]):
        self._sessions = sessions

    def create_organization(self, name: str) -> Organization:
        if not name.strip():
            raise ValueError("Organization name is required")
        with self._sessions.begin() as session:
            organization = Organization(name=name.strip())
            session.add(organization)
            session.flush()
            return organization

    def create_user(
        self,
        organization_id: str,
        *,
        email: str,
        password: str,
        role: str = "member",
    ) -> ApplicationUser:
        normalized_email = email.strip().lower()
        if "@" not in normalized_email:
            raise ValueError("A valid email address is required")
        if role not in {"owner", "admin", "member", "viewer"}:
            raise ValueError("Unsupported application role")
        with self._sessions.begin() as session:
            self._require_organization(session, organization_id)
            user = ApplicationUser(
                organization_id=organization_id,
                email=normalized_email,
                password_hash=hash_password(password),
                role=role,
            )
            session.add(user)
            session.flush()
            self._audit(
                session,
                organization_id,
                "application_user.created",
                actor_user_id=user.id,
                metadata={"user_id": user.id, "role": role},
            )
            return user

    def authenticate_user(self, organization_id: str, email: str, password: str) -> ApplicationUser | None:
        with self._sessions() as session:
            user = session.scalar(
                select(ApplicationUser).where(
                    ApplicationUser.organization_id == organization_id,
                    ApplicationUser.email == email.strip().lower(),
                    ApplicationUser.is_active.is_(True),
                )
            )
            return user if user and verify_password(user.password_hash, password) else None

    def issue_session(
        self,
        organization_id: str,
        user_id: str,
        *,
        ttl_seconds: int = 28_800,
    ) -> str:
        if not 300 <= ttl_seconds <= 604_800:
            raise ValueError("Application session TTL must be between 5 minutes and 7 days")
        raw_token = secrets.token_urlsafe(32)
        now = utcnow()
        with self._sessions.begin() as session:
            user = self._require_user(session, organization_id, user_id)
            if not user.is_active:
                raise InvalidStateError("Inactive application users cannot create sessions")
            application_session = ApplicationSession(
                organization_id=organization_id,
                user_id=user_id,
                token_hash=_token_hash(raw_token),
                expires_at=now + timedelta(seconds=ttl_seconds),
            )
            session.add(application_session)
            session.flush()
            self._audit(
                session,
                organization_id,
                "application_session.created",
                actor_user_id=user_id,
                metadata={"session_id": application_session.id},
            )
        return raw_token

    def authenticate_session(self, raw_token: str) -> ApplicationUser | None:
        if not raw_token:
            return None
        now = utcnow()
        with self._sessions.begin() as session:
            application_session = session.scalar(
                select(ApplicationSession).where(
                    ApplicationSession.token_hash == _token_hash(raw_token),
                    ApplicationSession.revoked_at.is_(None),
                    ApplicationSession.expires_at > now,
                )
            )
            if application_session is None:
                return None
            user = self._require_user(
                session, application_session.organization_id, application_session.user_id
            )
            if not user.is_active:
                return None
            application_session.last_seen_at = now
            return user

    def revoke_session(self, organization_id: str, user_id: str, session_id: str) -> None:
        with self._sessions.begin() as session:
            application_session = session.scalar(
                select(ApplicationSession).where(
                    ApplicationSession.id == session_id,
                    ApplicationSession.organization_id == organization_id,
                    ApplicationSession.user_id == user_id,
                )
            )
            if application_session is None:
                raise NotFoundError("Application session not found")
            application_session.revoked_at = utcnow()
            self._audit(
                session,
                organization_id,
                "application_session.revoked",
                actor_user_id=user_id,
                metadata={"session_id": session_id},
            )

    def create_scan(
        self,
        organization_id: str,
        created_by_id: str,
        *,
        target_identifier: str,
        request_budget: int = 50,
        deadline_seconds: int = 300,
        retention_days: int = 30,
    ) -> Scan:
        if not 1 <= request_budget <= 500:
            raise ValueError("Request budget must be between 1 and 500")
        if not 10 <= deadline_seconds <= 3600:
            raise ValueError("Deadline must be between 10 and 3600 seconds")
        if not 1 <= retention_days <= 365:
            raise ValueError("Retention must be between 1 and 365 days")
        target = _safe_target_identifier(target_identifier)
        now = utcnow()
        with self._sessions.begin() as session:
            self._require_user(session, organization_id, created_by_id)
            scan = Scan(
                organization_id=organization_id,
                created_by_id=created_by_id,
                target_identifier=target,
                request_budget=request_budget,
                deadline_at=now + timedelta(seconds=deadline_seconds),
                expires_at=now + timedelta(days=retention_days),
            )
            session.add(scan)
            session.flush()
            self._audit(
                session,
                organization_id,
                "scan.queued",
                actor_user_id=created_by_id,
                scan_id=scan.id,
                metadata={"request_budget": request_budget},
            )
            return scan

    def get_scan(self, organization_id: str, scan_id: str) -> Scan:
        with self._sessions() as session:
            return self._require_scan(session, organization_id, scan_id)

    def list_scans(self, organization_id: str, *, limit: int = 100) -> list[Scan]:
        if not 1 <= limit <= 500:
            raise ValueError("Limit must be between 1 and 500")
        with self._sessions() as session:
            return list(
                session.scalars(
                    select(Scan)
                    .where(Scan.organization_id == organization_id)
                    .order_by(Scan.created_at.desc())
                    .limit(limit)
                )
            )

    def store_credentials(
        self,
        organization_id: str,
        scan_id: str,
        payload: dict[str, Any],
        cipher: CredentialCipher,
        *,
        ttl_seconds: int = 600,
    ) -> None:
        if not 30 <= ttl_seconds <= 3600:
            raise ValueError("Credential TTL must be between 30 and 3600 seconds")
        now = utcnow()
        with self._sessions.begin() as session:
            scan = self._require_scan(session, organization_id, scan_id)
            if scan.status in TERMINAL_STATUSES:
                raise InvalidStateError("Credentials cannot be attached to a terminal scan")
            session.execute(delete(ScanCredential).where(ScanCredential.scan_id == scan.id))
            session.add(
                ScanCredential(
                    scan_id=scan.id,
                    encrypted_payload=cipher.encrypt(payload),
                    expires_at=min(now + timedelta(seconds=ttl_seconds), _utc(scan.deadline_at)),
                )
            )

    def load_credentials(
        self,
        organization_id: str,
        scan_id: str,
        cipher: CredentialCipher,
    ) -> dict[str, Any]:
        now = utcnow()
        with self._sessions.begin() as session:
            scan = self._require_scan(session, organization_id, scan_id)
            credential = session.scalar(
                select(ScanCredential).where(ScanCredential.scan_id == scan.id)
            )
            if credential is None:
                raise NotFoundError("No credentials are available for this scan")
            if _utc(credential.expires_at) <= now:
                session.delete(credential)
                raise InvalidStateError("Stored scan credentials have expired")
            return cipher.decrypt(credential.encrypted_payload)

    def claim_next_job(self, worker_id: str, *, lease_seconds: int = 60) -> Scan | None:
        if not worker_id.strip() or len(worker_id) > 128:
            raise ValueError("Worker ID is required and must be at most 128 characters")
        if not 10 <= lease_seconds <= 600:
            raise ValueError("Lease must be between 10 and 600 seconds")
        now = utcnow()
        with self._sessions.begin() as session:
            claimable = and_(
                Scan.deadline_at > now,
                or_(
                    Scan.status == "queued",
                    and_(
                        Scan.status.in_(("validating", "running")),
                        Scan.lease_expires_at.is_not(None),
                        Scan.lease_expires_at < now,
                    ),
                ),
            )
            statement = select(Scan).where(claimable).order_by(Scan.created_at)
            if session.bind and session.bind.dialect.name == "postgresql":
                statement = statement.with_for_update(skip_locked=True)
            candidate = session.scalar(statement.limit(1))
            if candidate is None:
                return None

            previous_status = candidate.status
            result = session.execute(
                update(Scan)
                .where(
                    Scan.id == candidate.id,
                    Scan.status == previous_status,
                    or_(
                        Scan.worker_id.is_(None),
                        Scan.lease_expires_at.is_(None),
                        Scan.lease_expires_at < now,
                    ),
                )
                .values(
                    status="validating",
                    worker_id=worker_id.strip(),
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                    attempt_count=Scan.attempt_count + 1,
                    started_at=Scan.started_at if candidate.started_at else now,
                )
            )
            if result.rowcount != 1:
                return None
            session.refresh(candidate)
            self._audit(
                session,
                candidate.organization_id,
                "scan.claimed",
                scan_id=candidate.id,
                metadata={"worker_id": worker_id.strip(), "attempt": candidate.attempt_count},
            )
            return candidate

    def transition_scan(
        self,
        organization_id: str,
        scan_id: str,
        new_status: str,
        *,
        worker_id: str | None = None,
        result: str | None = None,
        result_summary: dict[str, Any] | None = None,
        failure_code: str | None = None,
        secrets: Iterable[str] = (),
    ) -> Scan:
        now = utcnow()
        with self._sessions.begin() as session:
            scan = self._require_scan(session, organization_id, scan_id)
            if new_status not in ALLOWED_TRANSITIONS.get(scan.status, set()):
                raise InvalidStateError(f"Cannot transition scan from {scan.status} to {new_status}")
            if worker_id is not None and scan.worker_id != worker_id:
                raise InvalidStateError("The worker does not own this scan lease")
            scan.status = new_status
            if new_status == "running" and scan.started_at is None:
                scan.started_at = now
            if new_status in TERMINAL_STATUSES:
                scan.completed_at = now
                scan.worker_id = None
                scan.lease_expires_at = None
                session.execute(delete(ScanCredential).where(ScanCredential.scan_id == scan.id))
            scan.result = result
            scan.result_summary = _safe_summary(redact_value(result_summary, secrets))
            scan.failure_code = failure_code
            self._audit(
                session,
                organization_id,
                f"scan.{new_status}",
                scan_id=scan.id,
                metadata={"result": result, "failure_code": failure_code},
                secrets=secrets,
            )
            return scan

    def consume_request_budget(self, organization_id: str, scan_id: str, *, amount: int = 1) -> int:
        if amount <= 0:
            raise ValueError("Request budget amount must be positive")
        now = utcnow()
        with self._sessions.begin() as session:
            result = session.execute(
                update(Scan)
                .where(
                    Scan.id == scan_id,
                    Scan.organization_id == organization_id,
                    Scan.status.in_(("validating", "running")),
                    Scan.deadline_at > now,
                    Scan.request_count + amount <= Scan.request_budget,
                )
                .values(request_count=Scan.request_count + amount)
            )
            if result.rowcount != 1:
                self._require_scan(session, organization_id, scan_id)
                raise InvalidStateError("Scan request budget or deadline has been reached")
            return session.scalar(select(Scan.request_count).where(Scan.id == scan_id))

    def persist_report(
        self,
        organization_id: str,
        scan_id: str,
        report: dict[str, Any],
        *,
        secrets: Iterable[str] = (),
    ) -> None:
        safe_report = redact_value(report, secrets)
        with self._sessions.begin() as session:
            scan = self._require_scan(session, organization_id, scan_id)
            for endpoint in safe_report.get("tested_endpoints", []):
                key = {
                    "scan_id": scan.id,
                    "method": str(endpoint.get("method", "GET"))[:12],
                    "endpoint": str(endpoint.get("endpoint", "unknown"))[:512],
                }
                record = session.scalar(select(TestedEndpoint).filter_by(**key))
                if record is None:
                    record = TestedEndpoint(**key)
                    session.add(record)
                record.outcome = str(endpoint.get("outcome", "error"))
                record.reason = str(endpoint.get("reason", "No reason provided"))
                record.safe_details = {
                    key: endpoint[key]
                    for key in ("owner_a_id", "owner_b_id", "cross_user_status")
                    if key in endpoint and isinstance(endpoint[key], (str, int, float, bool, type(None)))
                }

            for finding in safe_report.get("findings", []):
                fingerprint = _finding_fingerprint(finding)
                record = session.scalar(
                    select(FindingRecord).where(
                        FindingRecord.scan_id == scan.id,
                        FindingRecord.fingerprint == fingerprint,
                    )
                )
                values = {
                    "category": str(finding.get("category", "unknown"))[:100],
                    "severity": str(finding.get("severity", "Low"))[:16],
                    "title": str(finding.get("title", "Untitled finding"))[:300],
                    "method": str(finding.get("method", "GET"))[:12],
                    "endpoint": str(finding.get("endpoint", "unknown"))[:512],
                    "evidence": str(finding.get("evidence", "")),
                    "expected_result": str(finding.get("expected_result", "")),
                    "actual_result": str(finding.get("actual_result", "")),
                    "remediation": str(finding.get("remediation", "")),
                    "safe_metadata": _safe_finding_metadata(finding.get("metadata", {})),
                }
                if record is None:
                    record = FindingRecord(scan_id=scan.id, fingerprint=fingerprint, **values)
                    session.add(record)
                else:
                    for field, value in values.items():
                        setattr(record, field, value)

            scan.result_summary = _safe_summary(safe_report.get("summary", {}))
            self._audit(
                session,
                organization_id,
                "scan.report_persisted",
                scan_id=scan.id,
                metadata={
                    "endpoint_count": len(safe_report.get("tested_endpoints", [])),
                    "finding_count": len(safe_report.get("findings", [])),
                },
            )

    def purge_expired(self, *, now: datetime | None = None) -> dict[str, int]:
        cutoff = now or utcnow()
        with self._sessions.begin() as session:
            application_sessions = session.execute(
                delete(ApplicationSession).where(
                    or_(
                        ApplicationSession.expires_at <= cutoff,
                        ApplicationSession.revoked_at.is_not(None),
                    )
                )
            ).rowcount
            credentials = session.execute(
                delete(ScanCredential).where(ScanCredential.expires_at <= cutoff)
            ).rowcount
            scans = session.execute(
                delete(Scan).where(
                    Scan.expires_at <= cutoff,
                    Scan.status.in_(tuple(TERMINAL_STATUSES)),
                )
            ).rowcount
            return {
                "application_sessions": application_sessions or 0,
                "credentials": credentials or 0,
                "scans": scans or 0,
            }

    def expire_overdue_jobs(self, *, now: datetime | None = None) -> int:
        cutoff = now or utcnow()
        with self._sessions.begin() as session:
            overdue_ids = list(
                session.scalars(
                    select(Scan.id).where(
                        Scan.deadline_at <= cutoff,
                        Scan.status.in_(("queued", "validating", "running")),
                    )
                )
            )
            if not overdue_ids:
                return 0
            session.execute(
                update(Scan)
                .where(Scan.id.in_(overdue_ids))
                .values(
                    status="expired",
                    completed_at=cutoff,
                    worker_id=None,
                    lease_expires_at=None,
                    failure_code="deadline_exceeded",
                )
            )
            session.execute(delete(ScanCredential).where(ScanCredential.scan_id.in_(overdue_ids)))
            return len(overdue_ids)

    def _require_organization(self, session: Session, organization_id: str) -> Organization:
        organization = session.get(Organization, organization_id)
        if organization is None:
            raise NotFoundError("Organization not found")
        return organization

    def _require_user(self, session: Session, organization_id: str, user_id: str) -> ApplicationUser:
        user = session.scalar(
            select(ApplicationUser).where(
                ApplicationUser.id == user_id,
                ApplicationUser.organization_id == organization_id,
            )
        )
        if user is None:
            raise NotFoundError("Application user not found")
        return user

    def _require_scan(self, session: Session, organization_id: str, scan_id: str) -> Scan:
        scan = session.scalar(
            select(Scan).where(Scan.id == scan_id, Scan.organization_id == organization_id)
        )
        if scan is None:
            raise NotFoundError("Scan not found")
        return scan

    def _audit(
        self,
        session: Session,
        organization_id: str,
        event_type: str,
        *,
        actor_user_id: str | None = None,
        scan_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        secrets: Iterable[str] = (),
    ) -> None:
        session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                scan_id=scan_id,
                event_type=event_type,
                safe_metadata=redact_value(metadata or {}, secrets),
            )
        )


def _safe_target_identifier(value: str) -> str:
    target = value.strip()
    if not target or len(target) > 512:
        raise ValueError("Target identifier is required and must be at most 512 characters")
    parsed = urlsplit(target)
    if parsed.username or parsed.password:
        raise ValueError("Target identifiers must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Target identifiers must not contain query strings or fragments")
    return target


def _finding_fingerprint(finding: dict[str, Any]) -> str:
    stable = {
        "category": finding.get("category"),
        "method": finding.get("method"),
        "endpoint": finding.get("endpoint"),
        "title": finding.get("title"),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode("utf-8")).hexdigest()


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _safe_summary(value: dict[str, Any] | None) -> dict[str, int] | None:
    if value is None:
        return None
    allowed = {
        "Critical",
        "High",
        "Medium",
        "Low",
        "Pass",
        "pass",
        "fail",
        "inconclusive",
        "error",
        "endpoint_count",
        "finding_count",
    }
    return {
        key: int(count)
        for key, count in value.items()
        if key in allowed and isinstance(count, int) and not isinstance(count, bool) and count >= 0
    }


def _safe_finding_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed = {
        "requesting_user",
        "target_owner",
        "owner_a_id",
        "owner_b_id",
        "exposed_fields",
        "attempts",
        "successful_responses",
    }
    return {key: value[key] for key in allowed if key in value}


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
