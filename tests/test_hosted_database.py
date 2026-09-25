import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from sqlalchemy import func, select

from app.hosted.config import HostedDatabaseSettings
from app.hosted.database import (
    create_hosted_engine,
    create_test_schema,
    health_check,
    hosted_session_factory,
    verify_schema_integrity,
)
from app.hosted.maintenance import backup_database, restore_database
from app.hosted.models import (
    ApplicationSession,
    AuditEvent,
    FindingRecord,
    Scan,
    ScanCredential,
    TestedEndpoint,
    utcnow,
)
from app.hosted.repository import HostedRepository, InvalidStateError, NotFoundError
from app.hosted.security import CredentialCipher


ROOT = Path(__file__).resolve().parent.parent


class HostedRepositoryTests(unittest.TestCase):
    def setUp(self):
        settings = HostedDatabaseSettings("test", "sqlite+pysqlite:///:memory:")
        self.engine = create_hosted_engine(settings, memory_test_database=True)
        create_test_schema(self.engine)
        self.sessions = hosted_session_factory(self.engine)
        self.repository = HostedRepository(self.sessions)
        self.organization_a = self.repository.create_organization("Organization A")
        self.organization_b = self.repository.create_organization("Organization B")
        self.user_a = self.repository.create_user(
            self.organization_a.id,
            email="owner-a@example.test",
            password="hosted-password-a",
            role="owner",
        )
        self.user_b = self.repository.create_user(
            self.organization_b.id,
            email="owner-b@example.test",
            password="hosted-password-b",
            role="owner",
        )
        self.cipher = CredentialCipher([Fernet.generate_key()])

    def tearDown(self):
        self.engine.dispose()

    def create_scan(self, *, budget=5):
        return self.repository.create_scan(
            self.organization_a.id,
            self.user_a.id,
            target_identifier="http://127.0.0.1:8000",
            request_budget=budget,
        )

    def test_users_are_hashed_and_scans_are_tenant_isolated(self):
        self.assertNotEqual(self.user_a.password_hash, "hosted-password-a")
        self.assertIsNotNone(
            self.repository.authenticate_user(
                self.organization_a.id, "OWNER-A@example.test", "hosted-password-a"
            )
        )
        scan = self.create_scan()

        with self.assertRaises(NotFoundError):
            self.repository.get_scan(self.organization_b.id, scan.id)
        with self.assertRaises(NotFoundError):
            self.repository.create_scan(
                self.organization_b.id,
                self.user_a.id,
                target_identifier="http://127.0.0.1:8000",
            )

    def test_scan_targets_are_restricted_to_local_http_origins(self):
        for target in (
            "https://127.0.0.1:8000",
            "http://example.test",
            "http://127.0.0.1:8000/path",
            "http://127.0.0.1:8000?token=secret",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.repository.create_scan(
                    self.organization_a.id,
                    self.user_a.id,
                    target_identifier=target,
                )

        scan = self.repository.create_scan(
            self.organization_a.id,
            self.user_a.id,
            target_identifier="http://localhost:8000/",
        )
        self.assertEqual(scan.target_identifier, "http://127.0.0.1:8000")

    def test_application_sessions_store_only_hashes_and_are_revocable(self):
        token = self.repository.issue_session(self.organization_a.id, self.user_a.id)
        with self.sessions() as session:
            stored = session.scalar(select(ApplicationSession))
            session_id = stored.id
            self.assertNotEqual(stored.token_hash, token)
            self.assertNotIn(token, stored.token_hash)
        authenticated = self.repository.authenticate_session(token)
        self.assertEqual(authenticated.id, self.user_a.id)
        self.repository.revoke_session(self.organization_a.id, self.user_a.id, session_id)
        self.assertIsNone(self.repository.authenticate_session(token))

    def test_credentials_are_encrypted_expire_and_are_deleted_at_completion(self):
        scan = self.create_scan()
        secret = "target-password-that-must-not-leak"
        self.repository.store_credentials(
            self.organization_a.id,
            scan.id,
            {"username": "scanner", "password": secret},
            self.cipher,
        )
        with self.sessions() as session:
            stored = session.scalar(select(ScanCredential).where(ScanCredential.scan_id == scan.id))
            self.assertNotIn(secret.encode(), stored.encrypted_payload)
        self.assertEqual(
            self.repository.load_credentials(self.organization_a.id, scan.id, self.cipher)["password"],
            secret,
        )

        claimed = self.repository.claim_next_job("worker-one")
        self.repository.transition_scan(
            self.organization_a.id, claimed.id, "running", worker_id="worker-one"
        )
        self.repository.transition_scan(
            self.organization_a.id,
            claimed.id,
            "completed",
            worker_id="worker-one",
            result="clean",
        )
        with self.assertRaises(NotFoundError):
            self.repository.load_credentials(self.organization_a.id, scan.id, self.cipher)

    def test_claiming_and_request_budget_are_atomic_and_bounded(self):
        scan = self.create_scan(budget=2)
        claimed = self.repository.claim_next_job("worker-one")
        self.assertEqual(claimed.id, scan.id)
        self.assertEqual(claimed.attempt_count, 1)
        self.assertIsNone(self.repository.claim_next_job("worker-two"))

        self.repository.transition_scan(
            self.organization_a.id, scan.id, "running", worker_id="worker-one"
        )
        self.assertEqual(self.repository.consume_request_budget(self.organization_a.id, scan.id), 1)
        self.assertEqual(self.repository.consume_request_budget(self.organization_a.id, scan.id), 2)
        with self.assertRaises(InvalidStateError):
            self.repository.consume_request_budget(self.organization_a.id, scan.id)

    def test_report_retries_are_idempotent_and_persist_only_redacted_evidence(self):
        scan = self.create_scan()
        secret = "report-secret-value"
        report = {
            "summary": {"Critical": 1},
            "tested_endpoints": [
                {
                    "method": "GET",
                    "endpoint": "/orders/{id}",
                    "outcome": "fail",
                    "reason": "Bearer raw-token exposed the object",
                    "response_body": {"private": secret},
                }
            ],
            "findings": [
                {
                    "category": "BOLA",
                    "severity": "Critical",
                    "title": "Broken Object Level Authorization",
                    "method": "GET",
                    "endpoint": "/orders/{id}",
                    "evidence": f"Bearer raw-token and {secret}",
                    "expected_result": "403",
                    "actual_result": "200",
                    "remediation": "Check ownership",
                    "metadata": {"password": secret, "raw_response": {"private": secret}},
                }
            ],
        }
        for _ in range(2):
            self.repository.persist_report(
                self.organization_a.id, scan.id, report, secrets=(secret, "raw-token")
            )

        with self.sessions() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(FindingRecord)), 1)
            self.assertEqual(session.scalar(select(func.count()).select_from(TestedEndpoint)), 1)
            finding = session.scalar(select(FindingRecord))
            endpoint = session.scalar(select(TestedEndpoint))
            audit_text = str(list(session.scalars(select(AuditEvent))))
        rendered = f"{finding.evidence} {finding.safe_metadata} {endpoint.reason} {audit_text}"
        self.assertNotIn(secret, rendered)
        self.assertNotIn("raw-token", rendered)
        self.assertNotIn("response_body", endpoint.safe_details)
        self.assertNotIn("raw_response", finding.safe_metadata)

    def test_retention_and_deadline_cleanup_remove_only_eligible_records(self):
        scan = self.create_scan()
        claimed = self.repository.claim_next_job("worker-one")
        self.repository.transition_scan(
            self.organization_a.id, claimed.id, "running", worker_id="worker-one"
        )
        self.repository.transition_scan(
            self.organization_a.id, claimed.id, "completed", worker_id="worker-one"
        )
        with self.sessions.begin() as session:
            stored = session.get(Scan, scan.id)
            stored.expires_at = utcnow() - timedelta(seconds=1)
        self.assertEqual(self.repository.purge_expired()["scans"], 1)
        with self.assertRaises(NotFoundError):
            self.repository.get_scan(self.organization_a.id, scan.id)

        overdue = self.create_scan()
        with self.sessions.begin() as session:
            session.get(Scan, overdue.id).deadline_at = utcnow() - timedelta(seconds=1)
        self.assertEqual(self.repository.expire_overdue_jobs(), 1)
        self.assertEqual(self.repository.get_scan(self.organization_a.id, overdue.id).status, "expired")


class HostedMigrationAndBackupTests(unittest.TestCase):
    def test_migration_health_backup_and_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "hosted.db"
            backup_path = Path(directory) / "hosted.backup.db"
            database_url = f"sqlite:///{database_path.as_posix()}"
            configuration = Config(str(ROOT / "alembic.ini"))
            configuration.set_main_option("script_location", str(ROOT / "migrations"))
            previous = os.environ.get("SENTINEL_DATABASE_URL")
            previous_environment = os.environ.get("SENTINEL_ENV")
            os.environ["SENTINEL_ENV"] = "test"
            os.environ["SENTINEL_DATABASE_URL"] = database_url
            try:
                command.upgrade(configuration, "head")
            finally:
                if previous is None:
                    os.environ.pop("SENTINEL_DATABASE_URL", None)
                else:
                    os.environ["SENTINEL_DATABASE_URL"] = previous
                if previous_environment is None:
                    os.environ.pop("SENTINEL_ENV", None)
                else:
                    os.environ["SENTINEL_ENV"] = previous_environment

            engine = create_hosted_engine(HostedDatabaseSettings("test", database_url))
            verify_schema_integrity(engine)
            self.assertEqual(health_check(engine)["status"], "ok")
            self.assertEqual(backup_database(engine, backup_path), backup_path.resolve())
            self.assertTrue(backup_path.is_file())
            restore_database(engine, backup_path)
            verify_schema_integrity(engine)
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
