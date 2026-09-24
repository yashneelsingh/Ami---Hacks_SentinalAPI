"""Bounded HTTP request execution for local scanner targets."""

from __future__ import annotations

from typing import Any

import httpx

from .models import BoundedResponse


class RequestExecutionError(ValueError):
    """A controlled transport failure safe to expose in scan outcomes."""


class HttpxRequestExecutor:
    def __init__(self, client: httpx.Client, *, max_response_bytes: int) -> None:
        self.client = client
        self.max_response_bytes = max_response_bytes

    def request(self, method: str, path: str, **kwargs: Any) -> BoundedResponse:
        try:
            request = self.client.build_request(method, path, **kwargs)
            response = self.client.send(request, stream=True)
            try:
                if 300 <= response.status_code < 400:
                    raise RequestExecutionError(f"Redirect blocked for {method.upper()} {path}")
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
            raise RequestExecutionError(f"Request timed out for {method.upper()} {path}") from None
        except httpx.ConnectError:
            raise RequestExecutionError(f"Could not connect for {method.upper()} {path}") from None
        except httpx.HTTPError:
            raise RequestExecutionError(f"Request failed for {method.upper()} {path}") from None

