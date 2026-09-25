"""Bounded, read-only two-user authorization scan for local sandbox APIs."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .authentication import AuthenticationError, PasswordAuthenticator
from .checks import check_excessive_data_exposure
from .comparison import ExactObjectComparator
from .interfaces import Authenticator, OwnershipComparator, Reporter, RequestExecutor
from .models import BoundedResponse, Credentials, Finding
from .openapi_parser import discover_object_endpoints, parse_spec
from .redaction import redact_value
from .report_generator import JsonReporter
from .request_execution import HttpxRequestExecutor, RequestExecutionError
from .severity import severity_for
from .structured_logging import configure_logging, log_event


REQUEST_TIMEOUT_SECONDS = 5.0
MAX_ENDPOINTS = 3
MAX_RESPONSE_BYTES = 1_000_000
logger = configure_logging()


class ScanError(ValueError):
    """A controlled, user-safe scanner failure."""


def validate_local_base_url(value: str) -> str:
    """Normalize an allowed local HTTP origin before it is persisted or used."""
    parts = urlsplit(value)
    if parts.scheme != "http" or parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ScanError("Target must be a local HTTP origin")
    if parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ScanError("Only local sandbox targets are supported")
    try:
        _ = parts.port
    except ValueError:
        raise ScanError("Target has an invalid port") from None
    # A numeric destination prevents a changed hosts entry or DNS answer from
    # turning the accepted localhost alias into an external connection.
    if parts.hostname == "localhost":
        return "http://127.0.0.1" + (f":{parts.port}" if parts.port is not None else "")
    return value.rstrip("/")


def _json(response: BoundedResponse, label: str) -> Any:
    try:
        return json.loads(response.content)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ScanError(f"{label} did not return JSON") from None


def _first_object(items: Any, owner_label: str) -> dict[str, Any]:
    if not isinstance(items, list) or not items or not isinstance(items[0], dict) or "id" not in items[0]:
        raise ScanError(f"{owner_label} has no discoverable object ID")
    object_id = items[0]["id"]
    if isinstance(object_id, bool) or not isinstance(object_id, (str, int)) or object_id == "":
        raise ScanError(f"{owner_label} has no usable object ID")
    return items[0]


def _detail_url(detail_path: str, parameter_name: str, object_id: Any) -> str:
    return detail_path.replace("{" + parameter_name + "}", quote(str(object_id), safe=""))


def _scan_endpoint(
    *, requester: RequestExecutor, comparator: OwnershipComparator, endpoint: Any, origin: str,
    token_a: str, token_b: str, user_a: Credentials, user_b: Credentials,
) -> tuple[list[Finding], dict[str, Any]]:
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    own_list_response = requester.request("GET", endpoint.collection_path, headers=headers_a)
    other_list_response = requester.request("GET", endpoint.collection_path, headers=headers_b)
    if own_list_response.status_code != 200 or other_list_response.status_code != 200:
        raise ScanError(f"Could not list both users' objects at {endpoint.collection_path}")
    own = _first_object(_json(own_list_response, "User A collection"), "User A")
    other = _first_object(_json(other_list_response, "User B collection"), "User B")
    tested: dict[str, Any] = {
        "method": "GET", "endpoint": endpoint.detail_path,
        "owner_a_id": own["id"], "owner_b_id": other["id"],
    }
    if str(own["id"]) == str(other["id"]):
        tested.update({
            "outcome": "inconclusive",
            "reason": "Both users received the same object ID; cross-user ownership could not be tested.",
        })
        return [], tested

    own_path = _detail_url(endpoint.detail_path, endpoint.parameter_name, own["id"])
    other_path = _detail_url(endpoint.detail_path, endpoint.parameter_name, other["id"])
    own_response = requester.request("GET", own_path, headers=headers_a)
    other_response = requester.request("GET", other_path, headers=headers_b)
    if own_response.status_code != 200 or other_response.status_code != 200:
        raise ScanError("Owner baseline request failed; cross-user result is inconclusive")
    own_body = _json(own_response, "User A object")
    other_body = _json(other_response, "User B object")
    if not isinstance(own_body, dict) or str(own_body.get("id")) != str(own["id"]):
        raise ScanError("User A owner baseline did not match the selected object ID")
    if not isinstance(other_body, dict) or str(other_body.get("id")) != str(other["id"]):
        raise ScanError("User B owner baseline did not match the selected object ID")
    cross_response = requester.request("GET", other_path, headers=headers_a)
    cross_body = _json(cross_response, "Cross-user object") if cross_response.status_code == 200 else None
    safe_request = {"method": "GET", "url": origin + other_path, "headers": {"Authorization": "Bearer <TEST_USER_TOKEN>"}}
    comparison = comparator.compare(
        cross_status=cross_response.status_code,
        cross_body=cross_body,
        owner_object_id=other["id"],
        owner_body=other_body,
    )
    tested.update({
        "cross_user_status": cross_response.status_code,
        "outcome": comparison.outcome,
        "reason": comparison.reason,
    })

    findings: list[Finding] = []
    if comparison.confirmed_bola:
        severity, score = severity_for("bola")
        findings.append(Finding(
            title="Broken Object Level Authorization", category="BOLA", severity=severity, score=score,
            endpoint=endpoint.detail_path, method="GET",
            evidence=f"{user_a.email} requested {other_path} (owned by {user_b.email}) and received HTTP 200 with the same object User B received.",
            expected_result="HTTP 403 or HTTP 404 for another user's object.",
            actual_result=f"HTTP 200; object ID {other['id']} was returned.",
            remediation="Verify object ownership before returning order details.", request=safe_request,
            metadata={"requesting_user": user_a.email, "target_owner": user_b.email, "owner_a_id": own["id"], "owner_b_id": other["id"]},
        ))
    own_request = {"method": "GET", "url": origin + own_path, "headers": {"Authorization": "Bearer <TEST_USER_TOKEN>"}}
    findings.extend(check_excessive_data_exposure(
        endpoint=endpoint.detail_path, method="GET", response_body=own_body, request=own_request,
    ))
    return findings, tested


def scan(
    *, spec: str | dict, base_url: str, user_a: Credentials, user_b: Credentials,
    transport: httpx.BaseTransport | None = None,
    authenticator: Authenticator | None = None,
    comparator: OwnershipComparator | None = None,
    reporter: Reporter | None = None,
) -> dict:
    """Compare two owners with bounded, read-only requests to a local target."""
    origin = validate_local_base_url(base_url)
    document = parse_spec(spec)
    endpoints = discover_object_endpoints(document)
    if not endpoints:
        raise ScanError("No authenticated GET /collection/{id} endpoint was found")
    if len(endpoints) > MAX_ENDPOINTS:
        raise ScanError(f"Specification exceeds the {MAX_ENDPOINTS}-endpoint scan limit")

    log_event(logger, "scan_started", target=origin, endpoint_count=len(endpoints))

    findings: list[Finding] = []
    tested: list[dict[str, Any]] = []
    discovered_secrets = [user_a.password, user_b.password]
    with httpx.Client(base_url=origin, timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS), follow_redirects=False, trust_env=False, transport=transport) as client:
        requester = HttpxRequestExecutor(client, max_response_bytes=MAX_RESPONSE_BYTES, validated_origin=origin)
        active_authenticator = authenticator or PasswordAuthenticator()
        active_comparator = comparator or ExactObjectComparator()
        active_reporter = reporter or JsonReporter()
        try:
            token_a = active_authenticator.authenticate(requester, user_a, "User A")
            token_b = active_authenticator.authenticate(requester, user_b, "User B")
        except (AuthenticationError, RequestExecutionError) as exc:
            raise ScanError(str(exc)) from None
        discovered_secrets.extend((token_a, token_b))
        log_event(logger, "authentication_completed", user_count=2)
        for endpoint in endpoints:
            try:
                endpoint_findings, endpoint_result = _scan_endpoint(
                    requester=requester, comparator=active_comparator, endpoint=endpoint, origin=origin,
                    token_a=token_a, token_b=token_b, user_a=user_a, user_b=user_b,
                )
                findings.extend(endpoint_findings)
                tested.append(endpoint_result)
                log_event(
                    logger,
                    "endpoint_test_completed",
                    secrets=discovered_secrets,
                    method="GET",
                    endpoint=endpoint.detail_path,
                    outcome=endpoint_result["outcome"],
                )
            except (ScanError, RequestExecutionError) as exc:
                tested.append({"method": "GET", "endpoint": endpoint.detail_path, "outcome": "error", "reason": str(exc)})
                log_event(
                    logger,
                    "endpoint_test_failed",
                    level=30,
                    secrets=discovered_secrets,
                    method="GET",
                    endpoint=endpoint.detail_path,
                    outcome="error",
                    reason=str(exc),
                )

    info = document.get("info")
    title = info.get("title", "Local sandbox API") if isinstance(info, dict) else "Local sandbox API"
    report = active_reporter.build(findings, target_name=str(title), secrets=discovered_secrets)
    safe_tested = redact_value(tested, discovered_secrets)
    report["tested_endpoints"] = safe_tested
    outcome_names = ("pass", "fail", "inconclusive", "error")
    report["outcomes"] = {
        outcome: [entry for entry in safe_tested if entry["outcome"] == outcome]
        for outcome in outcome_names
    }
    report["outcome_counts"] = {
        outcome: len(report["outcomes"][outcome]) for outcome in outcome_names
    }
    report["scan_status"] = "partial" if report["outcome_counts"]["error"] else "completed"
    if findings:
        report["result"] = "findings"
    elif any(endpoint["outcome"] in ("inconclusive", "error") for endpoint in tested):
        report["result"] = "inconclusive"
    else:
        report["result"] = "clean"
    log_event(
        logger,
        "scan_completed",
        secrets=discovered_secrets,
        result=report["result"],
        finding_count=len(findings),
        endpoint_count=len(tested),
    )
    return report
