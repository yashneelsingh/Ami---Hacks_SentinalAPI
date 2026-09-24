"""Safe, deterministic secondary checks over responses already collected by a scanner.

These functions do not issue network requests. The core scanner supplies controlled
responses from the local sandbox API, and this module evaluates them.
"""

from __future__ import annotations

from typing import Any, Iterable

from .models import Finding
from .severity import severity_for


SENSITIVE_FIELD_NAMES = {
    "password",
    "passwordhash",
    "secret",
    "token",
    "accesstoken",
    "refreshtoken",
    "paymentreference",
    "cardnumber",
    "cvv",
    "internalnotes",
    "ssn",
    "aadhaar",
}


def _flatten_keys(value: Any, prefix: str = "") -> list[str]:
    """Return dot paths for JSON keys, including nested object keys."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            found.append(path)
            found.extend(_flatten_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_flatten_keys(child, f"{prefix}[{index}]"))
    return found


def check_excessive_data_exposure(
    *,
    endpoint: str,
    method: str,
    response_body: Any,
    request: dict[str, Any],
    allowed_sensitive_fields: Iterable[str] = (),
) -> list[Finding]:
    """Flag likely sensitive fields returned to a normal user.

    `allowed_sensitive_fields` exists for endpoints where a field is explicitly
    justified. Field matching is case-insensitive and checks JSON key names only.
    """
    allowed = {field.lower() for field in allowed_sensitive_fields}
    exposed = []
    for key_path in _flatten_keys(response_body):
        field_name = key_path.rsplit(".", 1)[-1].split("[", 1)[0].lower()
        if field_name in SENSITIVE_FIELD_NAMES and field_name not in allowed:
            exposed.append(key_path)

    if not exposed:
        return []

    severity, score = severity_for("excessive data exposure", len(exposed))
    return [
        Finding(
            title="Excessive Data Exposure",
            category="Excessive Data Exposure",
            severity=severity,
            score=score,
            endpoint=endpoint,
            method=method.upper(),
            evidence="The response included sensitive field(s): " + ", ".join(exposed),
            expected_result="A normal user response should omit internal or secret fields.",
            actual_result="Sensitive fields were returned in the API response.",
            remediation=(
                "Return an allowlisted response DTO for this endpoint and exclude "
                "internal notes, payment references, tokens, and secrets."
            ),
            request=request,
            metadata={"exposed_fields": exposed},
        )
    ]


def check_rate_limit_observation(
    *,
    endpoint: str,
    method: str,
    attempts: int,
    successful_responses: int,
    request: dict[str, Any],
    safe_probe_limit: int = 10,
) -> list[Finding]:
    """Evaluate a small, pre-recorded rate-limit probe from the sandbox only.

    This deliberately caps the interpretation at a low number of requests; it is
    not a load test and must never be used against an unauthorized target.
    """
    if attempts <= 0 or attempts > safe_probe_limit:
        raise ValueError(f"attempts must be between 1 and {safe_probe_limit}")
    if successful_responses < 0 or successful_responses > attempts:
        raise ValueError("successful_responses must be between 0 and attempts")
    if successful_responses < attempts:
        return []

    severity, score = severity_for("missing rate limiting")
    return [
        Finding(
            title="Possible Missing Rate Limiting",
            category="Missing Rate Limiting",
            severity=severity,
            score=score,
            endpoint=endpoint,
            method=method.upper(),
            evidence=f"All {attempts} controlled sandbox requests succeeded without a limiting response.",
            expected_result="A sensitive endpoint should enforce a documented rate limit.",
            actual_result="No limiting response was observed during the safe low-volume probe.",
            remediation="Add endpoint-appropriate rate limiting and return HTTP 429 when the threshold is exceeded.",
            request=request,
            metadata={"attempts": attempts, "successful_responses": successful_responses},
        )
    ]

