import unittest
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.database import reset_database
from app.main import app
from scanner.core import Credentials, scan
from scanner.openapi_parser import discover_object_endpoints, parse_spec


ROOT = Path(__file__).resolve().parent.parent


class CoreScannerTests(unittest.TestCase):
    def setUp(self):
        reset_database()

    def test_openapi_discovers_order_detail(self):
        document = parse_spec((ROOT / "openapi.yaml").read_text(encoding="utf-8"))
        endpoints = discover_object_endpoints(document)
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].detail_path, "/orders/{order_id}")
        self.assertEqual(endpoints[0].collection_path, "/orders")
        self.assertEqual(discover_object_endpoints(parse_spec(app.openapi()))[0].detail_path, "/orders/{order_id}")

    def test_live_two_user_scan_confirms_bola_and_exposure(self):
        with TestClient(app) as target:
            def forward(request: httpx.Request) -> httpx.Response:
                response = target.request(request.method, request.url.path, headers=dict(request.headers), content=request.content)
                return httpx.Response(response.status_code, headers=dict(response.headers), content=response.content)

            report = scan(
                spec=(ROOT / "openapi.yaml").read_text(encoding="utf-8"),
                base_url="http://127.0.0.1:8000",
                user_a=Credentials("user-a@example.test", "demo-password-a"),
                user_b=Credentials("user-b@example.test", "demo-password-b"),
                transport=httpx.MockTransport(forward),
            )
        self.assertEqual(report["summary"]["Critical"], 1)
        self.assertEqual(report["summary"]["High"], 1)
        self.assertEqual(report["tested_endpoints"][0]["cross_user_status"], 200)
        self.assertNotIn("demo-token-user-a", str(report))

    def test_rejects_nonlocal_targets(self):
        with self.assertRaisesRegex(ValueError, "local sandbox"):
            scan(spec={}, base_url="http://example.com", user_a=Credentials("a", "b"), user_b=Credentials("c", "d"))


if __name__ == "__main__":
    unittest.main()
