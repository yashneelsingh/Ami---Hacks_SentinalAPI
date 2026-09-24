"""Create safe, copyable curl reproductions without leaking real tokens."""

from __future__ import annotations

import json
from typing import Any


def build_curl(request: dict[str, Any]) -> str:
    """Build a shell-friendly curl command from a recorded HTTP request.

    Authorization values are replaced with placeholders even when a caller passes
    a real local test token.
    """
    method = str(request.get("method", "GET")).upper()
    url = str(request.get("url", "http://localhost:5000"))
    headers = dict(request.get("headers", {}))
    body: Any = request.get("json")

    parts = [f"curl -X {method}", f'"{url}"']
    for name, value in headers.items():
        safe_value = "Bearer <TEST_USER_TOKEN>" if name.lower() == "authorization" else str(value)
        parts.append(f'-H "{name}: {safe_value}"')
    if body is not None:
        parts.append("-H \"Content-Type: application/json\"")
        parts.append("-d '" + json.dumps(body, separators=(",", ":")) + "'")
    return " ".join(parts)

