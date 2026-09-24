"""Create the hosted multi-tenant scan persistence schema.

Revision ID: 20260924_0001
Revises: None
Create Date: 2026-09-24
"""

from alembic import op
import sqlalchemy as sa


revision = "20260924_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "application_users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "email", name="uq_application_users_org_email"),
    )
    op.create_index(
        "ix_application_users_org_active",
        "application_users",
        ["organization_id", "is_active"],
    )
    op.create_table(
        "application_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["application_users.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_application_sessions_user_expires", "application_sessions", ["user_id", "expires_at"]
    )
    op.create_index("ix_application_sessions_expires_at", "application_sessions", ["expires_at"])
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("created_by_id", sa.String(36), nullable=False),
        sa.Column("target_identifier", sa.String(512), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_budget", sa.Integer(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(32)),
        sa.Column("result_summary", sa.JSON()),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("worker_id", sa.String(128)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["application_users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("request_budget > 0", name="ck_scans_positive_request_budget"),
        sa.CheckConstraint("request_count >= 0", name="ck_scans_nonnegative_request_count"),
        sa.CheckConstraint("request_count <= request_budget", name="ck_scans_request_budget"),
        sa.CheckConstraint(
            "status IN ('queued','validating','running','completed','failed','cancelled','expired')",
            name="ck_scans_status",
        ),
    )
    op.create_index("ix_scans_org_status_created", "scans", ["organization_id", "status", "created_at"])
    op.create_index("ix_scans_status_lease", "scans", ["status", "lease_expires_at"])
    op.create_index("ix_scans_expires_at", "scans", ["expires_at"])
    op.create_table(
        "tested_endpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("method", sa.String(12), nullable=False),
        sa.Column("endpoint", sa.String(512), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("safe_details", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id", "method", "endpoint", name="uq_tested_endpoints_scan_route"),
        sa.CheckConstraint(
            "outcome IN ('pass','fail','inconclusive','error')",
            name="ck_tested_endpoints_outcome",
        ),
    )
    op.create_index("ix_tested_endpoints_scan_outcome", "tested_endpoints", ["scan_id", "outcome"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("method", sa.String(12), nullable=False),
        sa.Column("endpoint", sa.String(512), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("expected_result", sa.Text(), nullable=False),
        sa.Column("actual_result", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
    )
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity"])
    op.create_table(
        "scan_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False, unique=True),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_scan_credentials_expires_at", "scan_credentials", ["expires_at"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("actor_user_id", sa.String(36)),
        sa.Column("scan_id", sa.String(36)),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["application_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_audit_events_org_created", "audit_events", ["organization_id", "created_at"])
    op.create_index("ix_audit_events_scan_created", "audit_events", ["scan_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_scan_created", table_name="audit_events")
    op.drop_index("ix_audit_events_org_created", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_scan_credentials_expires_at", table_name="scan_credentials")
    op.drop_table("scan_credentials")
    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_tested_endpoints_scan_outcome", table_name="tested_endpoints")
    op.drop_table("tested_endpoints")
    op.drop_index("ix_scans_expires_at", table_name="scans")
    op.drop_index("ix_scans_status_lease", table_name="scans")
    op.drop_index("ix_scans_org_status_created", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_application_sessions_expires_at", table_name="application_sessions")
    op.drop_index("ix_application_sessions_user_expires", table_name="application_sessions")
    op.drop_table("application_sessions")
    op.drop_index("ix_application_users_org_active", table_name="application_users")
    op.drop_table("application_users")
    op.drop_table("organizations")
