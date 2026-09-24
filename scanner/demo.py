"""Run the report module against controlled sample evidence.

Usage: python -m scanner.demo
"""

from pathlib import Path

from .checks import check_excessive_data_exposure, check_rate_limit_observation
from .models import Finding
from .report_generator import build_report, write_reports
from .severity import severity_for


def main() -> None:
    bola_severity, bola_score = severity_for("bola")
    bola_request = {
        "method": "GET",
        "url": "http://localhost:5000/orders/1002",
        "headers": {"Authorization": "Bearer local-demo-token"},
    }
    findings = [
        Finding(
            title="Broken Object Level Authorization",
            category="BOLA",
            severity=bola_severity,
            score=bola_score,
            endpoint="/orders/{id}",
            method="GET",
            evidence="User A requested order 1002, owned by User B, and received HTTP 200 with User B's order data.",
            expected_result="HTTP 403 or HTTP 404 because order 1002 is not owned by User A.",
            actual_result="HTTP 200 with another user's order data.",
            remediation="Verify resource ownership for every object ID before reading, updating, or deleting it.",
            request=bola_request,
            metadata={"requesting_user": "user-a@example.test", "target_owner": "user-b@example.test"},
        )
    ]
    findings.extend(
        check_excessive_data_exposure(
            endpoint="/orders/{id}",
            method="GET",
            response_body={"id": 1002, "itemName": "Laptop bag", "internalNotes": "VIP customer", "paymentReference": "pay_test_123"},
            request=bola_request,
        )
    )
    findings.extend(
        check_rate_limit_observation(
            endpoint="/auth/login",
            method="POST",
            attempts=5,
            successful_responses=5,
            request={"method": "POST", "url": "http://localhost:5000/auth/login", "json": {"email": "user-a@example.test"}},
        )
    )
    report = build_report(findings, target_name="Local intentionally vulnerable Order API")
    json_path, markdown_path = write_reports(report, Path("reports"))
    print(f"Created {json_path}")
    print(f"Created {markdown_path}")


if __name__ == "__main__":
    main()

