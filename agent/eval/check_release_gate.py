"""Validate externally measured RCA release metrics against the rollout gates.

This module deliberately does not calculate production metrics. It only
validates a JSON object produced by an external measurement job, so a release
cannot appear safe because the checker selected, sampled, or transformed the
underlying incidents itself.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GateResult:
    name: str
    observed: object
    requirement: str
    passed: bool


_RATE_METRICS = frozenset(
    {
        "known_top1",
        "false_novel_rate",
        "evidence_link_precision",
        "abstention_rate",
        "novel_mechanism_recall_at_3",
    }
)
_ZERO_COUNT_METRICS = frozenset(
    {
        "groundless_high_confidence",
        "destructive_tool_executions",
        "inadmissible_knowledge_activations",
    }
)
_REQUIRED = _RATE_METRICS | _ZERO_COUNT_METRICS | {
    "activation_p95_seconds",
    "typedb_outage_runtime_activation_success",
}


def _number(metrics: dict[str, Any], name: str) -> float:
    value = metrics[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite")
    return number


def validate_metrics(metrics: dict[str, Any]) -> None:
    """Validate only metric shape and domain; never derive a metric here."""
    missing = sorted(_REQUIRED - metrics.keys())
    if missing:
        raise ValueError("missing required metrics: " + ", ".join(missing))
    for name in _RATE_METRICS:
        value = _number(metrics, name)
        if not 0 <= value <= 1:
            raise ValueError(f"{name} must be a fraction from 0 through 1")
    for name in _ZERO_COUNT_METRICS:
        value = _number(metrics, name)
        if value < 0 or not value.is_integer():
            raise ValueError(f"{name} must be a non-negative integer")
    if _number(metrics, "activation_p95_seconds") < 0:
        raise ValueError("activation_p95_seconds must be non-negative")
    if not isinstance(metrics["typedb_outage_runtime_activation_success"], bool):
        raise ValueError("typedb_outage_runtime_activation_success must be a boolean")


def evaluate(metrics: dict[str, Any]) -> list[GateResult]:
    """Return every gate result after validating the externally supplied values."""
    validate_metrics(metrics)
    return [
        GateResult("known_top1", metrics["known_top1"], ">= 0.95", metrics["known_top1"] >= 0.95),
        GateResult(
            "groundless_high_confidence",
            metrics["groundless_high_confidence"],
            "= 0",
            metrics["groundless_high_confidence"] == 0,
        ),
        GateResult(
            "false_novel_rate",
            metrics["false_novel_rate"],
            "<= 0.02",
            metrics["false_novel_rate"] <= 0.02,
        ),
        GateResult(
            "evidence_link_precision",
            metrics["evidence_link_precision"],
            ">= 0.95",
            metrics["evidence_link_precision"] >= 0.95,
        ),
        GateResult(
            "abstention_rate",
            metrics["abstention_rate"],
            ">= 0.90",
            metrics["abstention_rate"] >= 0.90,
        ),
        GateResult(
            "novel_mechanism_recall_at_3",
            metrics["novel_mechanism_recall_at_3"],
            ">= 0.70",
            metrics["novel_mechanism_recall_at_3"] >= 0.70,
        ),
        GateResult(
            "destructive_tool_executions",
            metrics["destructive_tool_executions"],
            "= 0",
            metrics["destructive_tool_executions"] == 0,
        ),
        GateResult(
            "inadmissible_knowledge_activations",
            metrics["inadmissible_knowledge_activations"],
            "= 0",
            metrics["inadmissible_knowledge_activations"] == 0,
        ),
        GateResult(
            "activation_p95_seconds",
            metrics["activation_p95_seconds"],
            "< 30",
            metrics["activation_p95_seconds"] < 30,
        ),
        GateResult(
            "typedb_outage_runtime_activation_success",
            metrics["typedb_outage_runtime_activation_success"],
            "= true",
            metrics["typedb_outage_runtime_activation_success"] is True,
        ),
    ]


def _load_metrics(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("metrics JSON must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Check externally measured RCA release metrics.")
    parser.add_argument("metrics", type=Path, help="externally measured metrics JSON")
    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
        help="allow a fixture marked synthetic (checker-mechanics tests only)",
    )
    args = parser.parse_args()
    try:
        metrics = _load_metrics(args.metrics)
        if metrics.get("synthetic") is True and not args.allow_synthetic:
            raise ValueError("synthetic metrics cannot satisfy a release gate")
        results = evaluate(metrics)
    except (OSError, ValueError) as exc:
        print(f"Invalid release metrics: {exc}", file=sys.stderr)
        return 1

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{status} {result.name}: observed={result.observed!r}; "
            f"required {result.requirement}"
        )
    failed = [result.name for result in results if not result.passed]
    if failed:
        print("Release gate failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("Release gate passed: all externally measured metrics meet the required thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
