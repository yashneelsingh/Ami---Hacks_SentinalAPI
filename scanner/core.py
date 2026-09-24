"""Bounded, read-only two-user authorization scan for local sandbox APIs."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .checks import check_excessive_data_exposure
from .models import Finding
from .openapi_parser import discover_object_endpoints, parse_spec
from .redaction import redact_value
from .report_generator import build_report
from .severity import severity_for


REQUEST_TIMEOUT_SECONDS = 5.0
MAX_ENDPOINTS = 3
MAX_RESPONSE_BYTES = 1_000_000


class ScanError(ValueError):
    """A controlled, user-safe scanner failure."""


@dataclass(frozen=True)
class Credentials:
    email: str
    password: str


@dataclass(frozen=True)
class _BoundedResponse:
    status_code: int
    content: bytes


def _local_base_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "http" or parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ScanError("Target must be a local HTTP origin")
    if parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ScanError("Only local sandbox targets are supported")
    if parts.hostname != "localhost" and not ipaddress.ip_address(parts.hostname).is_loopback:
        raise ScanError("Only local sandbox targets are supported")
    return value.rstrip("/")


def _request(client: httpx.Client, method: str, path: str, **kwargs: Any) -> _BoundedResponse:
    """Issue one bounded request without exposing transport exception details."""
    try:
        request = client.build_request(method, path, **kwargs)
        response = client.send(request, stream=True)
        try:
            if 300 <= response.status_code < 400:
                raise ScanError(f"Redirect blocked for {method.upper()} {path}")
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = 0
                if declared_size > MAX_RESPONSE_BYTES:
                    raise ScanError(f"Response exceeded the {MAX_RESPONSE_BYTES}-byte limit")
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ScanError(f"Response exceeded the {MAX_RESPONSE_BYTES}-byte limit")
                chunks.append(chunk)
            return _BoundedResponse(response.status_code, b"".join(chunks))
        finally:
            response.close()
    except ScanError:
        raise
    except httpx.TimeoutException:
        raise ScanError(f"Request timed out for {method.upper()} {path}") from None
    except httpx.ConnectError:
        raise ScanError(f"Could not connect for {method.upper()} {path}") from None
    except httpx.HTTPError:
        raise ScanError(f"Request failed for {method.upper()} {path}") from None


def _json(response: _BoundedResponse, label: str) -> Any:
    try:
        return json.loads(response.content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ScanError(f"{label} did not return JSON") from None


def _login(client: httpx.Client, credentials: Credentials, user_label: str) -> str:
    response = _request(client, "POST", "/auth/login", json={"email": credentials.email, "password": credentials.password})
    if response.status_code != 200:
        raise ScanError(f"Login failed for {user_label} (HTTP {response.status_code})")
    body = _json(response, f"{user_label} login")
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise ScanError(f"{user_label} login response has no access_token")
    return token


def _first_object(items: Any, owner_label: str) -> dict[str, Any]:
    if not isinstance(items, list) or not items or not isinstance(items[0], dict) or "id" not in items[0]:
        raise ScanError(f"{owner_label} has no discoverable object ID")
    return items[0]


def _detail_url(detail_path: str, parameter_name: str, object_id: Any) -> str:
    return detail_path.replace("{" + parameter_name + "}", quote(str(object_id), safe=""))


def _scan_endpoint(
    *, client: httpx.Client, endpoint: Any, origin: str, token_a: str, token_b: str,
    user_a: Credentials, user_b: Credentials,
) -> tuple[list[Finding], dict[str, Any]]:
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    own_list_response = _request(client, "GET", endpoint.collection_path, headers=headers_a)
    other_list_response = _request(client, "GET", endpoint.collection_path, headers=headers_b)
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
    own_response = _request(client, "GET", own_path, headers=headers_a)
    other_response = _request(client, "GET", other_path, headers=headers_b)
    if own_response.status_code != 200 or other_response.status_code != 200:
        raise ScanError("Owner baseline request failed; cross-user result is inconclusive")
    own_body = _json(own_response, "User A object")
    other_body = _json(other_response, "User B object")
    cross_response = _request(client, "GET", other_path, headers=headers_a)
    cross_body = _json(cross_response, "Cross-user object") if cross_response.status_code == 200 else None
    safe_request = {"method": "GET", "url": origin + other_path, "headers": {"Authorization": "Bearer <TEST_USER_TOKEN>"}}
    confirmed_bola = (
        cross_response.status_code == 200 and isinstance(cross_body, dict) and isinstance(other_body, dict)
        and str(cross_body.get("id")) == str(other["id"]) and cross_body == other_body
    )
    if confirmed_bola:
        outcome, reason = "fail", "The requesting user received the same object returned to its owner."
    elif cross_response.status_code in (403, 404):
        outcome, reason = "pass", f"Cross-user access was denied with HTTP {cross_response.status_code}."
    else:
        outcome, reason = "inconclusive", "The response did not prove access to the other user's object."
    tested.update({"cross_user_status": cross_response.status_code, "outcome": outcome, "reason": reason})

    findings: list[Finding] = []
    if confirmed_bola:
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
) -> dict:
    """Compare two owners with bounded, read-only requests to a local target."""
    origin = _local_base_url(base_url)
    document = parse_spec(spec)
    endpoints = discover_object_endpoints(document)
    if not endpoints:
        raise ScanError("No authenticated GET /collection/{id} endpoint was found")
    if len(endpoints) > MAX_ENDPOINTS:
        raise ScanError(f"Specification exceeds the {MAX_ENDPOINTS}-endpoint scan limit")

    findings: list[Finding] = []
    tested: list[dict[str, Any]] = []
    discovered_secrets = [user_a.password, user_b.password]
    with httpx.Client(base_url=origin, timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS), follow_redirects=False, transport=transport) as client:
        token_a = _login(client, user_a, "User A")
        token_b = _login(client, user_b, "User B")
        discovered_secrets.extend((token_a, token_b))
        for endpoint in endpoints:
            try:
                endpoint_findings, endpoint_result = _scan_endpoint(
                    client=client, endpoint=endpoint, origin=origin, token_a=token_a, token_b=token_b,
                    user_a=user_a, user_b=user_b,
                )
                findings.extend(endpoint_findings)
                tested.append(endpoint_result)
            except ScanError as exc:
                tested.append({"method": "GET", "endpoint": endpoint.detail_path, "outcome": "error", "reason": str(exc)})

    info = document.get("info")
    title = info.get("title", "Local sandbox API") if isinstance(info, dict) else "Local sandbox API"
    report = build_report(findings, target_name=str(title), secrets=discovered_secrets)
    report["tested_endpoints"] = redact_value(tested, discovered_secrets)
    report["scan_status"] = "completed"
    if findings:
        report["result"] = "findings"
    elif any(endpoint["outcome"] in ("inconclusive", "error") for endpoint in tested):
        report["result"] = "inconclusive"
    else:
        report["result"] = "clean"
    return report
