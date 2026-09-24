from app.database import DATABASE_PATH, DEMO_SEED_VERSION, database_session, reset_database


if __name__ == "__main__":
    reset_database()
    with database_session() as connection:
        seeded_orders = connection.execute("SELECT id, owner_id FROM orders ORDER BY id").fetchall()
    seeded_order_owners = [(row["id"], row["owner_id"]) for row in seeded_orders]
    if seeded_order_owners != [(1001, 1), (1002, 2)]:
        raise RuntimeError("Reset did not restore the expected demo order ownership")

    order_summary = ", ".join(f"{order_id} (user {owner_id})" for order_id, owner_id in seeded_order_owners)
    print(f"Reset local SentinelAPI demo database at {DATABASE_PATH}.")
    print(f"Fixture version: {DEMO_SEED_VERSION}.")
    print(f"Verified seeded orders: {order_summary}.")
