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
        self.assertNotIn("patch", document["paths"]["/orders/{order_id}"])
        self.assertNotIn("patch", app.openapi()["paths"]["/orders/{order_id}"])
        endpoints = discover_object_endpoints(document)
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].detail_path, "/orders/{order_id}")
        self.assertEqual(endpoints[0].collection_path, "/orders")
        self.assertEqual(len(endpoints), 1)  # Nested support routes are not scanner targets.
        self.assertEqual(discover_object_endpoints(parse_spec(app.openapi()))[0].detail_path, "/orders/{order_id}")

    def test_jury_demo_specs_discover_only_the_supported_order_detail(self):
        demo_specs = ROOT / "demo-specs"
        expected_endpoints = {
            "orders-operation-security.yaml": ("/orders", "/orders/{order_id}"),
            "orders-root-security.yaml": ("/secure-orders", "/secure-orders/{order_id}"),
            "orders-mixed-routes.yaml": ("/unstable-orders", "/unstable-orders/{order_id}"),
        }
        self.assertEqual({path.name for path in demo_specs.glob("*.yaml")}, set(expected_endpoints))

        for spec_name, (collection_path, detail_path) in expected_endpoints.items():
            with self.subTest(spec=spec_name):
                document = parse_spec((demo_specs / spec_name).read_text(encoding="utf-8"))
                endpoints = discover_object_endpoints(document)
                self.assertEqual(len(endpoints), 1)
                self.assertEqual(endpoints[0].collection_path, collection_path)
                self.assertEqual(endpoints[0].detail_path, detail_path)
                self.assertEqual(endpoints[0].parameter_name, "order_id")

    def test_jury_demo_specs_complete_distinct_live_flows(self):
        demo_specs = ROOT / "demo-specs"
        expected_results = {
            "orders-operation-security.yaml": ("findings", "fail", 1, 1),
            "orders-root-security.yaml": ("clean", "pass", 0, 0),
            "orders-mixed-routes.yaml": ("inconclusive", "inconclusive", 0, 0),
        }

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

            for spec_path in sorted(demo_specs.glob("*.yaml")):
                with self.subTest(spec=spec_path.name):
                    expected_result, expected_outcome, critical, high = expected_results[spec_path.name]
                    report = scan(
                        spec=spec_path.read_text(encoding="utf-8"),
                        base_url="http://127.0.0.1:8000",
                        user_a=Credentials("user-a@example.test", "demo-password-a"),
                        user_b=Credentials("user-b@example.test", "demo-password-b"),
                        transport=httpx.MockTransport(forward),
                    )
                    self.assertEqual(report["scan_status"], "completed")
                    self.assertEqual(report["result"], expected_result)
                    self.assertEqual(report["summary"]["Critical"], critical)
                    self.assertEqual(report["summary"]["High"], high)
                    self.assertEqual(len(report["tested_endpoints"]), 1)
                    self.assertEqual(report["tested_endpoints"][0]["outcome"], expected_outcome)

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

    def test_unexpected_cross_user_status_is_inconclusive(self):
        for status in (401, 429, 500):
            with self.subTest(status=status):
                report = self._controlled_scan(cross_status=status, cross_body={"detail": "unavailable"})
                self.assertEqual(report["result"], "inconclusive")
                self.assertEqual(report["tested_endpoints"][0]["outcome"], "inconclusive")
                self.assertEqual(report["findings"], [])

    def test_owner_baseline_id_mismatch_is_error(self):
        def respond(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/auth/login":
                email = json.loads(request.content)["email"]
                return httpx.Response(200, json={"access_token": "token-a" if email.startswith("user-a") else "token-b"})
            if request.url.path == "/orders":
                return httpx.Response(200, json=[{"id": 1001 if request.headers["authorization"].endswith("a") else 1002}])
            return httpx.Response(200, json={"id": 9999})

        report = scan(
            spec=(ROOT / "openapi.yaml").read_text(encoding="utf-8"),
            base_url="http://127.0.0.1:8000",
            user_a=Credentials("user-a@example.test", "demo-password-a"),
            user_b=Credentials("user-b@example.test", "demo-password-b"),
            transport=httpx.MockTransport(respond),
        )
        self.assertEqual(report["result"], "inconclusive")
        self.assertEqual(report["scan_status"], "partial")
        self.assertEqual(report["tested_endpoints"][0]["outcome"], "error")
        self.assertEqual(report["findings"], [])

    def test_non_scalar_collection_id_is_error(self):
        def respond(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/auth/login":
                return httpx.Response(200, json={"access_token": "token"})
            return httpx.Response(200, json=[{"id": {"nested": 1001}}])

        report = scan(
            spec=(ROOT / "openapi.yaml").read_text(encoding="utf-8"),
            base_url="http://127.0.0.1:8000",
            user_a=Credentials("user-a@example.test", "demo-password-a"),
            user_b=Credentials("user-b@example.test", "demo-password-b"),
            transport=httpx.MockTransport(respond),
        )
        self.assertEqual(report["result"], "inconclusive")
        self.assertEqual(report["tested_endpoints"][0]["outcome"], "error")
        self.assertEqual(report["findings"], [])

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
