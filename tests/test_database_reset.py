import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from app import database
from app.main import app
from scanner.core import Credentials, scan


EXPECTED_USERS = [
    (1, "user-a@example.test", "demo-password-a", "customer"),
    (2, "user-b@example.test", "demo-password-b", "customer"),
]
EXPECTED_ORDERS = [
    (1001, 1, "SentinelAPI Hoodie", 49.99, "1 Demo Lane, Test City", "Customer prefers blue packaging.", "pay_demo_a_1001"),
    (1002, 2, "SentinelAPI Mug", 17.5, "2 Sandbox Road, Test City", "Do not disclose this internal fulfillment note.", "pay_demo_b_1002"),
]
ROOT = Path(__file__).resolve().parent.parent


class DatabaseResetTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "nested" / "sentinel_demo.db"
        self.path_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.temporary_directory.cleanup()

    def snapshot(self):
        with database.database_session() as connection:
            users = connection.execute(
                "SELECT id, email, password, role FROM users ORDER BY id"
            ).fetchall()
            orders = connection.execute(
                """
                SELECT id, owner_id, item_name, amount, shipping_address,
                       internal_notes, payment_reference
                FROM orders ORDER BY id
                """
            ).fetchall()
        return [tuple(row) for row in users], [tuple(row) for row in orders]

    def test_reset_creates_database_and_exact_seed_data(self):
        self.assertFalse(self.database_path.exists())

        database.reset_database()

        self.assertTrue(self.database_path.is_file())
        self.assertEqual(self.snapshot(), (EXPECTED_USERS, EXPECTED_ORDERS))
        with database.database_session() as connection:
            metadata = dict(connection.execute("SELECT key, value FROM demo_metadata").fetchall())
        self.assertEqual(metadata["schema_version"], database.DEMO_SCHEMA_VERSION)
        self.assertEqual(metadata["seed_version"], database.DEMO_SEED_VERSION)

    def test_startup_rejects_malformed_or_corrupt_database_with_reset_guidance(self):
        self.database_path.parent.mkdir(parents=True)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(database.DemoDatabaseError, "run python -m app.seed"):
            database.ensure_database()

        self.database_path.unlink()
        self.database_path.write_bytes(b"not a sqlite database")
        with self.assertRaisesRegex(database.DemoDatabaseError, "corrupt or unreadable"):
            database.ensure_database()

    def test_reset_reseeds_modified_database_and_is_repeatable(self):
        database.reset_database()
        with database.database_session() as connection:
            connection.execute("UPDATE orders SET owner_id = 1 WHERE id = 1002")
            connection.execute("DELETE FROM orders WHERE id = 1001")
            connection.execute(
                """
                INSERT INTO orders
                    (id, owner_id, item_name, amount, shipping_address, internal_notes, payment_reference)
                VALUES (9999, 1, 'Unexpected order', 1, 'Changed', 'Changed', 'Changed')
                """
            )

        database.reset_database()
        first_reset = self.snapshot()
        database.reset_database()

        self.assertEqual(first_reset, (EXPECTED_USERS, EXPECTED_ORDERS))
        self.assertEqual(self.snapshot(), first_reset)

    def test_reset_keeps_file_usable_when_an_existing_handle_is_open(self):
        database.reset_database()
        existing_handle = sqlite3.connect(self.database_path)
        try:
            existing_handle.execute("SELECT 1").fetchone()

            database.reset_database()

            order_ids = existing_handle.execute("SELECT id FROM orders ORDER BY id").fetchall()
            self.assertEqual(order_ids, [(1001,), (1002,)])
        finally:
            existing_handle.close()

    def test_foreign_key_rejects_order_with_unknown_owner(self):
        database.reset_database()
        seeded_state = self.snapshot()

        with self.assertRaises(sqlite3.IntegrityError):
            with database.database_session() as connection:
                connection.execute(
                    """
                    INSERT INTO orders
                        (id, owner_id, item_name, amount, shipping_address,
                         internal_notes, payment_reference)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (9999, 999, "Invalid order", 1.0, "Nowhere", "None", "pay_invalid"),
                )

        self.assertEqual(self.snapshot(), seeded_state)

    def test_failed_transaction_rolls_back_all_changes(self):
        database.reset_database()
        seeded_state = self.snapshot()

        with self.assertRaisesRegex(RuntimeError, "force rollback"):
            with database.database_session() as connection:
                connection.execute(
                    "INSERT INTO users (id, email, password, role) VALUES (?, ?, ?, ?)",
                    (3, "rollback@example.test", "temporary-password", "customer"),
                )
                connection.execute(
                    """
                    INSERT INTO orders
                        (id, owner_id, item_name, amount, shipping_address,
                         internal_notes, payment_reference)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (1003, 3, "Temporary order", 5.0, "Temporary", "Temporary", "pay_temporary"),
                )
                raise RuntimeError("force rollback")

        self.assertEqual(self.snapshot(), seeded_state)

    def test_repeated_scans_have_same_findings_and_do_not_mutate_database(self):
        database.reset_database()
        seeded_state = self.snapshot()

        with TestClient(app) as target:
            def forward(request: httpx.Request) -> httpx.Response:
                response = target.request(
                    request.method,
                    request.url.path,
                    headers=dict(request.headers),
                    content=request.content,
                )
                return httpx.Response(
                    response.status_code,
                    headers=dict(response.headers),
                    content=response.content,
                )

            reports = [
                scan(
                    spec=(ROOT / "openapi.yaml").read_text(encoding="utf-8"),
                    base_url="http://127.0.0.1:8000",
                    user_a=Credentials("user-a@example.test", "demo-password-a"),
                    user_b=Credentials("user-b@example.test", "demo-password-b"),
                    transport=httpx.MockTransport(forward),
                )
                for _ in range(2)
            ]

        self.assertEqual(reports[0]["summary"], reports[1]["summary"])
        self.assertEqual(reports[0]["findings"], reports[1]["findings"])
        self.assertEqual(reports[0]["tested_endpoints"], reports[1]["tested_endpoints"])
        self.assertEqual(self.snapshot(), seeded_state)


if __name__ == "__main__":
    unittest.main()
