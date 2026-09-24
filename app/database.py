from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "sentinel_demo.db"
DATABASE_BUSY_TIMEOUT_SECONDS = 10

USERS = [
    (1, "user-a@example.test", "demo-password-a", "customer"),
    (2, "user-b@example.test", "demo-password-b", "customer"),
]

ORDERS = [
    (1001, 1, "SentinelAPI Hoodie", 49.99, "1 Demo Lane, Test City", "Customer prefers blue packaging.", "pay_demo_a_1001"),
    (1002, 2, "SentinelAPI Mug", 17.50, "2 Sandbox Road, Test City", "Do not disclose this internal fulfillment note.", "pay_demo_b_1002"),
]


def connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_BUSY_TIMEOUT_SECONDS)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {DATABASE_BUSY_TIMEOUT_SECONDS * 1000}")
    return connection


@contextmanager
def database_session() -> Iterator[sqlite3.Connection]:
    connection = connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def reset_database() -> None:
    """Atomically restore deterministic data without replacing the SQLite file.

    Keeping the existing file makes reset work on Windows even when the local API
    process has an open handle. ``BEGIN IMMEDIATE`` also ensures another writer
    cannot observe or create a partially seeded database.
    """
    with database_session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TABLE IF EXISTS orders")
        connection.execute("DROP TABLE IF EXISTS users")
        connection.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                item_name TEXT NOT NULL,
                amount REAL NOT NULL,
                shipping_address TEXT NOT NULL,
                internal_notes TEXT NOT NULL,
                payment_reference TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
            """
        )
        connection.executemany(
            "INSERT INTO users (id, email, password, role) VALUES (?, ?, ?, ?)",
            USERS,
        )
        connection.executemany(
            """
            INSERT INTO orders
                (id, owner_id, item_name, amount, shipping_address, internal_notes, payment_reference)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ORDERS,
        )


def ensure_database() -> None:
    if not DATABASE_PATH.exists():
        reset_database()
