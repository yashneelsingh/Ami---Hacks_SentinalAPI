"""Ownership comparison policy for BOLA detection."""

from __future__ import annotations

from typing import Any

from .models import ComparisonResult


class ExactObjectComparator:
    def compare(
        self,
        *,
        cross_status: int,
        cross_body: Any,
        owner_object_id: Any,
        owner_body: Any,
    ) -> ComparisonResult:
        confirmed = (
            cross_status == 200
            and isinstance(cross_body, dict)
            and isinstance(owner_body, dict)
            and str(cross_body.get("id")) == str(owner_object_id)
            and cross_body == owner_body
        )
        if confirmed:
            return ComparisonResult(
                outcome="fail",
                reason="The requesting user received the same object returned to its owner.",
                confirmed_bola=True,
            )
        if cross_status in (403, 404):
            return ComparisonResult(
                outcome="pass",
                reason=f"Cross-user access was denied with HTTP {cross_status}.",
                confirmed_bola=False,
            )
        return ComparisonResult(
            outcome="inconclusive",
            reason="The response did not prove access to the other user's object.",
            confirmed_bola=False,
        )

