"""Shared data structures for SentinelAPI reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Outcome = Literal["pass", "fail", "inconclusive", "error"]


@dataclass(frozen=True)
class Credentials:
    email: str
    password: str


@dataclass(frozen=True)
class BoundedResponse:
    status_code: int
    content: bytes


@dataclass(frozen=True)
class ComparisonResult:
    outcome: Outcome
    reason: str
    confirmed_bola: bool


@dataclass
class Finding:
    """A confirmed or informational result from a controlled API scan."""

    title: str
    category: str
    severity: str
    score: float
    endpoint: str
    method: str
    evidence: str
    expected_result: str
    actual_result: str
    remediation: str
    request: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
