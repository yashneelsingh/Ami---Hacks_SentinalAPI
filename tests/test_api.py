import unittest

from fastapi.testclient import TestClient

from app.database import reset_database
from app.main import app


class VulnerableDemoTests(unittest.TestCase):
    def setUp(self):
        reset_database()
        self.client = TestClient(app)

    def test_user_a_cannot_list_user_b_order(self):
        response = self.client.get("/orders", headers={"Authorization": "Bearer demo-token-user-a"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{"id": 1001, "item_name": "SentinelAPI Hoodie", "amount": 49.99, "shipping_address": "1 Demo Lane, Test City"}])

    def test_seeded_idor_allows_user_a_to_read_user_b_order(self):
        response = self.client.get("/orders/1002", headers={"Authorization": "Bearer demo-token-user-a"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["owner_id"], 2)
        self.assertIn("internal_notes", response.json())
        self.assertIn("payment_reference", response.json())

    def test_order_endpoint_requires_token(self):
        response = self.client.get("/orders/1001")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
