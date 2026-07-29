"""Small, shared ontology value normalizers."""

from __future__ import annotations

from typing import Any


_CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.7, "low": 0.4}
_MISSING_WORKLOAD_NAMESPACE = "__missing_namespace__"


def workload_uid(namespace: Any, name: Any) -> str:
    """Return the graph identity for a Kubernetes workload."""
    name = str(name or "").strip()
    if not name:
        return ""
    # Missing namespaces are kept separate rather than falling back to the
    # bare name: the sentinel cannot be a Kubernetes namespace, but cannot
    # later resolve to a namespaced workload either.
    namespace = str(namespace or "").strip() or _MISSING_WORKLOAD_NAMESPACE
    return f"{namespace}/{name}"


def confidence_score(value: Any) -> float | None:
    """Return the compatible numeric confidence, if this is a known bucket."""
    return _CONFIDENCE_SCORES.get(str(value or "").strip().lower())
