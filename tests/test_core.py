import json
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
        self.assertEqual(report["outcome_counts"], {"pass": 0, "fail": 1, "inconclusive": 0, "error": 0})
        self.assertEqual(report["outcomes"]["fail"], report["tested_endpoints"])
        self.assertNotIn("demo-token-user-a", str(report))

    def _controlled_scan(self, *, cross_status=403, cross_body=None, same_object_id=False):
        """Run against deterministic live HTTP responses without a second API app."""
        object_a = {"id": 1001, "item_name": "Owner A item"}
        object_b = {"id": 1001 if same_object_id else 1002, "item_name": "Owner B item"}

        def respond(request: httpx.Request) -> httpx.Response:
            authorization = request.headers.get("authorization")
            if request.url.path == "/auth/login":
                email = json.loads(request.content)["email"]
                token = "token-a" if email == "user-a@example.test" else "token-b"
                return httpx.Response(200, json={"access_token": token})
            if request.url.path == "/orders":
                return httpx.Response(200, json=[object_a if authorization == "Bearer token-a" else object_b])
            if request.url.path == f"/orders/{object_a['id']}":
                return httpx.Response(200, json=object_a)
            if request.url.path == f"/orders/{object_b['id']}" and authorization == "Bearer token-b":
                return httpx.Response(200, json=object_b)
            if request.url.path == f"/orders/{object_b['id']}" and authorization == "Bearer token-a":
                return httpx.Response(cross_status, json=cross_body)
            return httpx.Response(404, json={"detail": "Not found"})

        return scan(
            spec=(ROOT / "openapi.yaml").read_text(encoding="utf-8"),
            base_url="http://127.0.0.1:8000",
            user_a=Credentials("user-a@example.test", "demo-password-a"),
            user_b=Credentials("user-b@example.test", "demo-password-b"),
            transport=httpx.MockTransport(respond),
        )

    def test_secure_403_produces_clean_report_without_bola(self):
        report = self._controlled_scan(cross_status=403, cross_body={"detail": "Forbidden"})
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["scan_status"], "completed")
        self.assertEqual(report["result"], "clean")
        self.assertEqual(report["tested_endpoints"][0]["outcome"], "pass")
        self.assertEqual(report["outcome_counts"], {"pass": 1, "fail": 0, "inconclusive": 0, "error": 0})

    def test_secure_404_produces_no_bola(self):
        report = self._controlled_scan(cross_status=404, cross_body={"detail": "Not found"})
        self.assertFalse(any(finding["category"] == "BOLA" for finding in report["findings"]))
        self.assertEqual(report["tested_endpoints"][0]["outcome"], "pass")

    def test_mismatched_or_malformed_200_does_not_prove_victim_object(self):
        for body in ({"id": 9999, "item_name": "Different item"}, ["not", "an", "object"]):
            with self.subTest(body=body):
                report = self._controlled_scan(cross_status=200, cross_body=body)
                self.assertFalse(any(finding["category"] == "BOLA" for finding in report["findings"]))
                self.assertEqual(report["result"], "inconclusive")
                self.assertEqual(report["tested_endpoints"][0]["outcome"], "inconclusive")

    def test_same_object_id_is_reported_as_inconclusive(self):
        report = self._controlled_scan(same_object_id=True)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["result"], "inconclusive")
        self.assertEqual(report["tested_endpoints"][0]["outcome"], "inconclusive")

    def test_rejects_nonlocal_targets(self):
        with self.assertRaisesRegex(ValueError, "local sandbox"):
            scan(spec={}, base_url="http://example.com", user_a=Credentials("a", "b"), user_b=Credentials("c", "d"))


if __name__ == "__main__":
    unittest.main()
