import unittest

from fastapi.testclient import TestClient

from app.database import reset_database
from app.main import app
from app.secure_main import app as secure_app


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


class SecureControlTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(secure_app)

    def _token(self, email: str, password: str) -> str:
        response = self.client.post("/auth/login", json={"email": email, "password": password})
        self.assertEqual(response.status_code, 200)
        return response.json()["access_token"]

    def test_cross_user_order_is_forbidden_and_owner_response_is_allowlisted(self):
        token = self._token("user-a@example.test", "demo-password-a")
        headers = {"Authorization": f"Bearer {token}"}

        own_response = self.client.get("/orders/1001", headers=headers)
        cross_response = self.client.get("/orders/1002", headers=headers)

        self.assertEqual(own_response.status_code, 200)
        self.assertNotIn("internal_notes", own_response.json())
        self.assertNotIn("payment_reference", own_response.json())
        self.assertEqual(cross_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
