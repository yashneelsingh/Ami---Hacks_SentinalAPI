import json
import tempfile
import unittest
from pathlib import Path

from scanner.checks import check_excessive_data_exposure, check_rate_limit_observation
from scanner.reproduction import build_curl
from scanner.report_generator import REPORT_SCHEMA_VERSION, build_report, markdown_report, write_reports


ROOT = Path(__file__).resolve().parent.parent


class ScannerModuleTests(unittest.TestCase):
    def test_json_report_includes_schema_version(self):
        report = build_report([], "secure target")

        self.assertEqual(report["version"], REPORT_SCHEMA_VERSION)
        with tempfile.TemporaryDirectory() as output_dir:
            json_path, _ = write_reports(report, output_dir)
            serialized_report = json.loads(json_path.read_text(encoding="utf-8"))

        self.assertEqual(serialized_report["version"], REPORT_SCHEMA_VERSION)

    def test_data_exposure_flags_internal_fields(self):
        findings = check_excessive_data_exposure(
            endpoint="/orders/1002",
            method="GET",
            response_body={"id": 1002, "internalNotes": "private", "paymentReference": "pay_123"},
            request={"method": "GET", "url": "http://localhost:5000/orders/1002"},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "High")
        self.assertIn("internalNotes", findings[0].evidence)

    def test_data_exposure_flags_seeded_api_snake_case_fields(self):
        findings = check_excessive_data_exposure(
            endpoint="/orders/{order_id}",
            method="GET",
            response_body={"internal_notes": "private", "payment_reference": "pay_demo_1002"},
            request={"method": "GET", "url": "http://127.0.0.1:8000/orders/1002"},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["exposed_fields"], ["internal_notes", "payment_reference"])

    def test_rate_limit_check_is_bounded(self):
        with self.assertRaises(ValueError):
            check_rate_limit_observation(
                endpoint="/auth/login", method="POST", attempts=11, successful_responses=11, request={}
            )

    def test_curl_masks_authorization_value(self):
        command = build_curl(
            {"method": "GET", "url": "http://localhost:5000/orders/1002", "headers": {"Authorization": "Bearer secret"}}
        )
        self.assertIn("<TEST_USER_TOKEN>", command)
        self.assertNotIn("Bearer secret", command)

    def test_markdown_report_contains_reproduction(self):
        finding = check_excessive_data_exposure(
            endpoint="/profile", method="GET", response_body={"token": "do-not-return"}, request={"url": "http://localhost:5000/profile"}
        )[0]
        report = build_report([finding], "test target")
        self.assertIn("Safe reproduction command", markdown_report(report))

    def test_markdown_report_identifies_successful_clean_scan(self):
        report = build_report([], "secure target")
        report.update({"scan_status": "completed", "result": "clean"})
        markdown = markdown_report(report)
        self.assertIn("**Scan status:** Completed", markdown)
        self.assertIn("**Result:** Clean", markdown)
        self.assertIn("completed successfully with no confirmed findings", markdown)

    def test_markdown_report_lists_endpoint_outcomes_separately(self):
        report = build_report([], "secure target")
        report["outcome_counts"] = {"pass": 2, "fail": 1, "inconclusive": 3, "error": 4}
        markdown = markdown_report(report)
        self.assertIn("## Endpoint outcomes", markdown)
        self.assertIn("| 2 | 1 | 3 | 4 |", markdown)

    def test_dashboard_renders_clean_scan_as_complete(self):
        dashboard_script = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('"No confirmed findings."', dashboard_script)
        self.assertIn('setScanState("TESTING OBJECT OWNERSHIP…", "running")', dashboard_script)
        self.assertIn('setScanState("SCAN COMPLETE", "done")', dashboard_script)
        self.assertIn('setScanState("SCAN FAILED", "failed")', dashboard_script)

    def test_dashboard_uses_only_local_assets_and_report_downloads(self):
        dashboard = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
        dashboard_script = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertNotIn('src="http://', dashboard)
        self.assertNotIn('src="https://', dashboard)
        self.assertIn('/api/reports/sentinel_report.${format}', dashboard_script)


if __name__ == "__main__":
    unittest.main()

