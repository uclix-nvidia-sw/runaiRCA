"""Small, shared ontology value normalizers."""

from __future__ import annotations

from typing import Any


_CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.7, "low": 0.4}


def confidence_score(value: Any) -> float | None:
    """Return the compatible numeric confidence, if this is a known bucket."""
    return _CONFIDENCE_SCORES.get(str(value or "").strip().lower())
