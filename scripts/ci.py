"""Reset the deterministic demo database and run the complete test suite."""

from __future__ import annotations

import sys
import unittest

from app.database import ORDERS, USERS, database_session, reset_database


def verify_seed_data() -> None:
    with database_session() as connection:
        users = [tuple(row) for row in connection.execute(
            "SELECT id, email, password, role FROM users ORDER BY id"
        ).fetchall()]
        orders = [tuple(row) for row in connection.execute(
            """SELECT id, owner_id, item_name, amount, shipping_address,
                      internal_notes, payment_reference
               FROM orders ORDER BY id"""
        ).fetchall()]
    if users != USERS or orders != ORDERS:
        raise RuntimeError("Database reset did not restore the exact deterministic seed data")


def main() -> int:
    reset_database()
    verify_seed_data()
    print("Verified deterministic SentinelAPI seed data.")
    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())

