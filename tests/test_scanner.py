import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from scanner.checks import check_excessive_data_exposure, check_rate_limit_observation
from scanner.reproduction import build_curl
from scanner.report_generator import REPORT_SCHEMA_VERSION, build_report, markdown_report, write_reports


ROOT = Path(__file__).resolve().parent.parent


class ScannerModuleTests(unittest.TestCase):
    def test_json_report_includes_schema_version(self):
        report = build_report([], "secure target")

        self.assertEqual(report["version"], REPORT_SCHEMA_VERSION)
        self.assertEqual(report["schema_version"], REPORT_SCHEMA_VERSION)
        with tempfile.TemporaryDirectory() as output_dir:
            json_path, _ = write_reports(report, output_dir)
            serialized_report = json.loads(json_path.read_text(encoding="utf-8"))

        self.assertEqual(serialized_report["version"], REPORT_SCHEMA_VERSION)

    def test_report_pair_is_consistent_and_survives_failed_replacement(self):
        with tempfile.TemporaryDirectory() as output_dir:
            first = build_report([], "first")
            json_path, markdown_path = write_reports(first, output_dir)
            original_json = json_path.read_bytes()
            original_markdown = markdown_path.read_bytes()
            second = build_report([], "second")
            from scanner import report_generator

            real_replace = report_generator.os.replace
            attempts = 0

            def fail_second_replacement(source, destination):
                nonlocal attempts
                attempts += 1
                if attempts == 2:
                    raise OSError("synthetic failure")
                return real_replace(source, destination)

            with patch.object(report_generator.os, "replace", side_effect=fail_second_replacement):
                with self.assertRaises(OSError):
                    write_reports(second, output_dir)
            self.assertEqual(json_path.read_bytes(), original_json)
            self.assertEqual(markdown_path.read_bytes(), original_markdown)
            self.assertEqual(
                sorted(path.name for path in Path(output_dir).iterdir()),
                ["sentinel_report.json", "sentinel_report.md"],
            )
            write_reports(second, output_dir)
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["target"], "second")
            self.assertIn("**Target:** second", markdown_path.read_text(encoding="utf-8"))

    def test_report_serialization_failure_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as output_dir:
            json_path, markdown_path = write_reports(build_report([], "original"), output_dir)
            report = build_report([], "new")
            report["unserializable"] = object()
            with self.assertRaises(TypeError):
                write_reports(report, output_dir)
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["target"], "original")
            self.assertIn("**Target:** original", markdown_path.read_text(encoding="utf-8"))

    def test_concurrent_report_writers_leave_matching_formats(self):
        with tempfile.TemporaryDirectory() as output_dir:
            reports = [build_report([], f"target-{index}") for index in range(8)]
            with ThreadPoolExecutor(max_workers=4) as workers:
                list(workers.map(lambda report: write_reports(report, output_dir), reports))
            json_path = Path(output_dir) / "sentinel_report.json"
            markdown_path = Path(output_dir) / "sentinel_report.md"
            saved = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn(f"**Target:** {saved['target']}", markdown)
            self.assertIn(saved["generated_at"], markdown)
            self.assertEqual(
                sorted(path.name for path in Path(output_dir).iterdir()),
                ["sentinel_report.json", "sentinel_report.md"],
            )

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

    def test_nested_exposure_reports_paths_without_values(self):
        findings = check_excessive_data_exposure(
            endpoint="/orders/{id}",
            method="GET",
            response_body={
                "internal": {"payment_reference": "payment-marker"},
                "items": [{"internal_notes": "note-marker"}],
            },
            request={},
        )
        self.assertEqual(
            findings[0].metadata["exposed_fields"],
            ["internal.payment_reference", "items[0].internal_notes"],
        )
        self.assertNotIn("payment-marker", findings[0].evidence)
        self.assertNotIn("note-marker", findings[0].evidence)

    def test_deep_response_key_walk_is_iterative(self):
        body = {"internal_notes": "secret-marker"}
        for _ in range(1200):
            body = [body]
        findings = check_excessive_data_exposure(endpoint="/orders/{id}", method="GET", response_body=body, request={})
        self.assertEqual(len(findings), 1)
        self.assertIn("internal_notes", findings[0].evidence)
        self.assertNotIn("secret-marker", findings[0].evidence)

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
        self.assertIn('setScanState("Testing object ownership', dashboard_script)
        self.assertIn('report.result === "clean"', dashboard_script)
        self.assertIn('setScanState("Scan failed", "failed")', dashboard_script)

    def test_dashboard_uses_only_local_assets_and_report_downloads(self):
        dashboard = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
        dashboard_script = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertNotIn('src="http://', dashboard)
        self.assertNotIn('src="https://', dashboard)
        self.assertIn('/api/reports/sentinel_report.${format}', dashboard_script)


if __name__ == "__main__":
    unittest.main()

