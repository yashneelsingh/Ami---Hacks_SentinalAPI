"""Bounded, read-only two-user authorization scan for local sandbox APIs."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import httpx

from .checks import check_excessive_data_exposure
from .models import Finding
from .openapi_parser import discover_object_endpoints, parse_spec
from .report_generator import build_report
from .severity import severity_for


@dataclass(frozen=True)
class Credentials:
    email: str
    password: str


def _local_base_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "http" or parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("Target must be a local HTTP origin")
    if parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Only local sandbox targets are supported")
    if parts.hostname != "localhost" and not ipaddress.ip_address(parts.hostname).is_loopback:
        raise ValueError("Only local sandbox targets are supported")
    return value.rstrip("/")


def _json(response: httpx.Response, label: str):
    try:
        return response.json()
    except ValueError as exc:
        raise ValueError(f"{label} did not return JSON") from exc


def _login(client: httpx.Client, credentials: Credentials) -> str:
    response = client.post("/auth/login", json={"email": credentials.email, "password": credentials.password})
    if response.status_code != 200:
        raise ValueError(f"Login failed for {credentials.email} (HTTP {response.status_code})")
    token = _json(response, "Login").get("access_token")
    if not isinstance(token, str) or not token:
        raise ValueError("Login response has no access_token")
    return token


def _first_order(items, owner_label: str) -> dict:
    if not isinstance(items, list) or not items or not isinstance(items[0], dict) or "id" not in items[0]:
        raise ValueError(f"{owner_label} has no discoverable order ID")
    return items[0]


def scan(
    *,
    spec: str | dict,
    base_url: str,
    user_a: Credentials,
    user_b: Credentials,
    transport: httpx.BaseTransport | None = None,
) -> dict:
    """Compare two owners with a bounded number of read-only object requests."""
    origin = _local_base_url(base_url)
    document = parse_spec(spec)
    endpoints = discover_object_endpoints(document)
    if not endpoints:
        raise ValueError("No authenticated GET /collection/{id} endpoint was found")

    findings: list[Finding] = []
    tested = []
    with httpx.Client(base_url=origin, timeout=5.0, follow_redirects=False, transport=transport) as client:
        token_a = _login(client, user_a)
        token_b = _login(client, user_b)
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        for endpoint in endpoints[:3]:
            own_list = client.get(endpoint.collection_path, headers=headers_a)
            other_list = client.get(endpoint.collection_path, headers=headers_b)
            if own_list.status_code != 200 or other_list.status_code != 200:
                raise ValueError(f"Could not list both users' objects at {endpoint.collection_path}")
            own = _first_order(_json(own_list, "User A collection"), "User A")
            other = _first_order(_json(other_list, "User B collection"), "User B")
            if str(own["id"]) == str(other["id"]):
                raise ValueError("Both users received the same object ID; ownership comparison is inconclusive")

            def detail_url(object_id):
                return endpoint.detail_path.replace("{" + endpoint.parameter_name + "}", quote(str(object_id), safe=""))

            own_response = client.get(detail_url(own["id"]), headers=headers_a)
            other_response = client.get(detail_url(other["id"]), headers=headers_b)
            if own_response.status_code != 200 or other_response.status_code != 200:
                raise ValueError("Owner baseline request failed; cross-user result would be inconclusive")
            own_body = _json(own_response, "User A object")
            other_body = _json(other_response, "User B object")
            cross_path = detail_url(other["id"])
            cross_response = client.get(cross_path, headers=headers_a)
            cross_body = _json(cross_response, "Cross-user object") if cross_response.status_code == 200 else None
            request = {"method": "GET", "url": origin + cross_path, "headers": {"Authorization": "Bearer <TEST_USER_TOKEN>"}}
            tested.append({"method": "GET", "endpoint": endpoint.detail_path, "owner_a_id": own["id"], "owner_b_id": other["id"], "cross_user_status": cross_response.status_code})

            if (
                cross_response.status_code == 200
                and isinstance(cross_body, dict)
                and isinstance(other_body, dict)
                and str(cross_body.get("id")) == str(other["id"])
                and cross_body == other_body
            ):
                severity, score = severity_for("bola")
                findings.append(Finding(
                    title="Broken Object Level Authorization",
                    category="BOLA",
                    severity=severity,
                    score=score,
                    endpoint=endpoint.detail_path,
                    method="GET",
                    evidence=f"{user_a.email} requested {cross_path} (owned by {user_b.email}) and received HTTP 200 with the same object User B received.",
                    expected_result="HTTP 403 or HTTP 404 for another user's object.",
                    actual_result=f"HTTP 200; object ID {other['id']} was returned.",
                    remediation="Verify object ownership before returning order details.",
                    request=request,
                    metadata={"requesting_user": user_a.email, "target_owner": user_b.email, "owner_a_id": own["id"], "owner_b_id": other["id"]},
                ))

            own_request = {"method": "GET", "url": origin + detail_url(own["id"]), "headers": {"Authorization": "Bearer <TEST_USER_TOKEN>"}}
            findings.extend(check_excessive_data_exposure(
                endpoint=endpoint.detail_path,
                method="GET",
                response_body=own_body,
                request=own_request,
            ))

    report = build_report(findings, target_name=document.get("info", {}).get("title", "Local sandbox API"))
    report["tested_endpoints"] = tested
    return report
