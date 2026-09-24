import json
import traceback
import unittest
from copy import deepcopy

import httpx
from fastapi.testclient import TestClient

from app.main import app
from scanner.core import MAX_ENDPOINTS, MAX_RESPONSE_BYTES, Credentials, ScanError, scan
from scanner.openapi_parser import MAX_SPEC_BYTES, parse_spec
from scanner.redaction import redact_value
from scanner.report_generator import build_report, markdown_report
from scanner.models import Finding
from scanner.reproduction import build_curl


BASE_SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "Safety test"},
    "paths": {
        "/orders": {"get": {"security": [{"bearerAuth": []}]}},
        "/orders/{id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [{"name": "id", "in": "path"}],
            }
        },
    },
}
USERS = (Credentials("a@example.test", "password-a-secret"), Credentials("b@example.test", "password-b-secret"))


def run_scan(handler, spec=None):
    return scan(
        spec=spec or BASE_SPEC,
        base_url="http://127.0.0.1:8000",
        user_a=USERS[0],
        user_b=USERS[1],
        transport=httpx.MockTransport(handler),
    )


def successful_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/auth/login":
        email = json.loads(request.content)["email"]
        return httpx.Response(200, json={"access_token": "secret-token-a" if email.startswith("a") else "secret-token-b"})
    authorization = request.headers.get("authorization")
    if request.url.path == "/orders":
        return httpx.Response(200, json=[{"id": 1 if authorization.endswith("a") else 2}])
    if request.url.path == "/orders/1":
        return httpx.Response(200, json={"id": 1})
    if request.url.path == "/orders/2":
        return httpx.Response(200, json={"id": 2})
    return httpx.Response(404)


class OpenApiSafetyTests(unittest.TestCase):
    def test_invalid_unsupported_and_missing_openapi_fields_are_clear(self):
        cases = [
            ("paths: [", "Invalid OpenAPI document"),
            ({"openapi": "2.0", "paths": {}}, "OpenAPI 3.x"),
            ({"openapi": "3.1.0"}, "missing paths"),
            ({"openapi": "3.1.0", "paths": []}, "paths must be an object"),
        ]
        for source, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                parse_spec(source)

    def test_missing_authenticated_object_endpoint_is_clear(self):
        with self.assertRaisesRegex(ScanError, "No authenticated GET"):
            run_scan(successful_handler, {"openapi": "3.1.0", "paths": {}})

    def test_spec_size_is_bounded_and_yaml_tags_are_not_executed(self):
        with self.assertRaisesRegex(ValueError, "byte limit"):
            parse_spec("x" * (MAX_SPEC_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "Invalid OpenAPI document"):
            parse_spec("!!python/object/apply:os.system ['echo unsafe']")

    def test_scan_upload_size_error_is_bounded_and_does_not_echo_content(self):
        marker = "uploaded-secret-marker"
        with TestClient(app) as client:
            response = client.post("/api/scan", json={"spec": marker + "x" * MAX_SPEC_BYTES})
        self.assertEqual(response.status_code, 413)
        self.assertIn("byte limit", response.json()["detail"])
        self.assertNotIn(marker, response.text)

    def test_endpoint_count_is_bounded(self):
        spec = {"openapi": "3.1.0", "paths": {}}
        for index in range(MAX_ENDPOINTS + 1):
            collection = f"/things-{index}"
            spec["paths"][collection] = {"get": {"security": [{"bearerAuth": []}]}}
            spec["paths"][collection + "/{id}"] = {
                "get": {"security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path"}]}
            }
        with self.assertRaisesRegex(ScanError, "endpoint scan limit"):
            run_scan(successful_handler, spec)


class TransportSafetyTests(unittest.TestCase):
    def test_login_failure_missing_token_and_non_json_are_controlled(self):
        cases = [
            (lambda _: httpx.Response(401, text="password-a-secret secret-token-a"), "Login failed for User A"),
            (lambda _: httpx.Response(200, json={}), "has no access_token"),
            (lambda _: httpx.Response(200, text="secret-token-a"), "did not return JSON"),
        ]
        for handler, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ScanError, message) as raised:
                run_scan(handler)
            self.assertNotIn("password-a-secret", str(raised.exception))
            self.assertNotIn("secret-token-a", str(raised.exception))

    def test_connection_refusal_timeout_and_redirect_are_controlled(self):
        def refused(request):
            raise httpx.ConnectError("Bearer secret-token-a", request=request)

        def timed_out(request):
            raise httpx.ReadTimeout("password-a-secret", request=request)

        for handler, message in ((refused, "Could not connect"), (timed_out, "timed out")):
            with self.subTest(message=message), self.assertRaisesRegex(ScanError, message) as raised:
                try:
                    run_scan(handler)
                except ScanError:
                    rendered_traceback = traceback.format_exc()
                    raise
            self.assertNotIn("secret-token", str(raised.exception))
            self.assertNotIn("password-a-secret", str(raised.exception))
            self.assertNotIn("secret-token-a", rendered_traceback)
            self.assertNotIn("password-a-secret", rendered_traceback)

        with self.assertRaisesRegex(ScanError, "Redirect blocked"):
            run_scan(lambda _: httpx.Response(302, headers={"location": "http://example.com"}))

    def test_non_json_object_and_oversized_response_become_inconclusive(self):
        def non_json_object(request):
            response = successful_handler(request)
            return httpx.Response(200, text="not-json") if request.url.path == "/orders/1" else response

        report = run_scan(non_json_object)
        self.assertEqual(report["result"], "inconclusive")
        self.assertEqual(report["tested_endpoints"][0]["outcome"], "error")
        self.assertIn("did not return JSON", report["tested_endpoints"][0]["reason"])

        def oversized(request):
            if request.url.path == "/orders":
                return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
            return successful_handler(request)

        report = run_scan(oversized)
        self.assertEqual(report["tested_endpoints"][0]["outcome"], "error")
        self.assertIn("byte limit", report["tested_endpoints"][0]["reason"])

    def test_timeout_configuration_and_partial_endpoint_failure(self):
        seen_timeouts = []
        spec = deepcopy(BASE_SPEC)
        spec["paths"].update({
            "/widgets": {"get": {"security": [{"bearerAuth": []}]}},
            "/widgets/{id}": {"get": {"security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path"}]}},
        })

        def handler(request):
            seen_timeouts.append(request.extensions.get("timeout"))
            if request.url.path.startswith("/widgets"):
                raise httpx.ReadTimeout("partial failure", request=request)
            return successful_handler(request)

        report = run_scan(handler, spec)
        outcomes = {entry["endpoint"]: entry["outcome"] for entry in report["tested_endpoints"]}
        self.assertEqual(outcomes["/orders/{id}"], "fail")
        self.assertEqual(outcomes["/widgets/{id}"], "error")
        self.assertTrue(all(timeout and timeout["read"] == 5.0 for timeout in seen_timeouts))


class RedactionSafetyTests(unittest.TestCase):
    def test_redacts_headers_bodies_reports_and_markdown(self):
        secret = "ultra-secret-password"
        request = {
            "method": "POST",
            "url": "http://localhost/auth/login",
            "headers": {"Authorization": "Bearer real-token", "X-Note": "Bearer second-token"},
            "json": {"email": "a@example.test", "password": secret, "access_token": "body-token"},
        }
        rendered = build_curl(request)
        self.assertNotIn("real-token", rendered)
        self.assertNotIn("second-token", rendered)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("body-token", rendered)

        finding = Finding(
            title="test", category="test", severity="Low", score=1.0, endpoint="/test", method="GET",
            evidence=f"Bearer real-token and {secret}", expected_result="safe", actual_result=secret,
            remediation="safe", request=request, metadata={"token": "metadata-token"},
        )
        report = build_report([finding], secret, secrets=[secret, "real-token", "metadata-token", "body-token"])
        serialized = json.dumps(report) + markdown_report(report)
        for leaked in (secret, "real-token", "metadata-token", "body-token", "second-token"):
            self.assertNotIn(leaked, serialized)

    def test_recursive_redaction_does_not_mutate_input(self):
        original = {"headers": {"authorization": "Bearer token-value"}, "password": "password-value"}
        safe = redact_value(original)
        self.assertEqual(original["password"], "password-value")
        self.assertEqual(safe["password"], "<REDACTED>")


if __name__ == "__main__":
    unittest.main()
