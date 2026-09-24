"""Bounded HTTP request execution for local scanner targets."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from .models import BoundedResponse
from .openapi_parser import validate_openapi_path


class RequestExecutionError(ValueError):
    """A controlled transport failure safe to expose in scan outcomes."""


class HttpxRequestExecutor:
    def __init__(self, client: httpx.Client, *, max_response_bytes: int, validated_origin: str) -> None:
        self.client = client
        self.max_response_bytes = max_response_bytes
        self.validated_origin = _origin_tuple(validated_origin)

    def request(self, method: str, path: str, **kwargs: Any) -> BoundedResponse:
        try:
            if method.upper() != "GET" and not (method.upper() == "POST" and path == "/auth/login"):
                raise RequestExecutionError("Only GET and controlled login requests are permitted")
            try:
                validate_openapi_path(path)
            except ValueError:
                raise RequestExecutionError("Request path is not a safe origin-relative route") from None
            request = self.client.build_request(method, path, **kwargs)
            if _origin_tuple(str(request.url)) != self.validated_origin:
                raise RequestExecutionError("Request destination differs from the validated local origin")
            response = self.client.send(request, stream=True)
            try:
                if 300 <= response.status_code < 400:
                    raise RequestExecutionError("Redirect blocked")
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        declared_size = 0
                    if declared_size > self.max_response_bytes:
                        raise RequestExecutionError(
                            f"Response exceeded the {self.max_response_bytes}-byte limit"
                        )
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise RequestExecutionError(
                            f"Response exceeded the {self.max_response_bytes}-byte limit"
                        )
                    chunks.append(chunk)
                return BoundedResponse(response.status_code, b"".join(chunks))
            finally:
                response.close()
        except RequestExecutionError:
            raise
        except httpx.TimeoutException:
            raise RequestExecutionError("Request timed out") from None
        except httpx.ConnectError:
            raise RequestExecutionError("Could not connect to local target") from None
        except httpx.HTTPError:
            raise RequestExecutionError("Request to local target failed") from None
        except ValueError:
            raise RequestExecutionError("Invalid local request") from None


def _origin_tuple(url: str) -> tuple[str, str, int]:
    """Compare the effective HTTP destination before credentials reach transport."""
    parts = urlsplit(url)
    try:
        port = parts.port if parts.port is not None else 80
    except ValueError:
        raise RequestExecutionError("Invalid request destination") from None
    if parts.scheme != "http" or parts.hostname not in ("localhost", "127.0.0.1", "::1") or parts.username or parts.password:
        raise RequestExecutionError("Request destination is not an allowed local HTTP origin")
    return parts.scheme, parts.hostname, port

