"""Deterministic severity scoring for the local SentinelAPI demo."""

from __future__ import annotations


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Pass": 0}


def severity_for(category: str, sensitive_field_count: int = 0) -> tuple[str, float]:
    """Return a transparent severity label and score for a confirmed finding."""
    normalized = category.strip().lower()

    if normalized in {"bola", "idor", "broken object level authorization"}:
        return "Critical", 9.5
    if normalized == "excessive data exposure":
        if sensitive_field_count >= 3:
            return "High", 8.0
        return "High", 7.0
    if normalized in {"missing rate limiting", "weak rate limiting"}:
        return "Medium", 5.5
    return "Low", 2.5


def sort_key(finding: object) -> tuple[int, float]:
    """Sort highest-risk findings first without coupling to a report type."""
    severity = getattr(finding, "severity", "Pass")
    score = float(getattr(finding, "score", 0.0))
    return SEVERITY_ORDER.get(severity, 0), score

