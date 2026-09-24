"""Typed boundaries between the scanner's orchestration components."""

from __future__ import annotations

from typing import Any, Iterable, Protocol

from .models import BoundedResponse, ComparisonResult, Credentials, Finding


class RequestExecutor(Protocol):
    def request(self, method: str, path: str, **kwargs: Any) -> BoundedResponse:
        """Execute one bounded request and return its buffered response."""


class Authenticator(Protocol):
    def authenticate(self, requester: RequestExecutor, credentials: Credentials, user_label: str) -> str:
        """Authenticate one controlled test identity and return its token."""


class OwnershipComparator(Protocol):
    def compare(
        self,
        *,
        cross_status: int,
        cross_body: Any,
        owner_object_id: Any,
        owner_body: Any,
    ) -> ComparisonResult:
        """Classify whether a cross-user response proves unauthorized access."""


class Reporter(Protocol):
    def build(self, findings: Iterable[Finding], target_name: str, *, secrets: Iterable[str] = ()) -> dict:
        """Build the serializable scan report."""

