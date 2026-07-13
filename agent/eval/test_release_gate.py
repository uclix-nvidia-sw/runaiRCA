"""Synthetic tests for release-gate checker mechanics, never release metrics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.check_release_gate import evaluate, validate_metrics

_EVAL_DIR = Path(__file__).parent


def _fixture(name: str) -> dict[str, object]:
    return json.loads((_EVAL_DIR / name).read_text())


def test_synthetic_passing_fixture_exercises_threshold_boundaries() -> None:
    results = evaluate(_fixture("release_gate.synthetic.pass.json"))

    assert all(result.passed for result in results)


def test_synthetic_failing_fixture_exercises_every_gate() -> None:
    results = evaluate(_fixture("release_gate.synthetic.fail.json"))

    assert [result.name for result in results if not result.passed] == [
        "known_top1",
        "groundless_high_confidence",
        "false_novel_rate",
        "evidence_link_precision",
        "abstention_rate",
        "novel_mechanism_recall_at_3",
        "destructive_tool_executions",
        "inadmissible_knowledge_activations",
        "activation_p95_seconds",
        "typedb_outage_runtime_activation_success",
    ]


def test_missing_or_invalid_external_metrics_are_rejected() -> None:
    with pytest.raises(ValueError, match="missing required metrics"):
        validate_metrics({})

    bad = _fixture("release_gate.synthetic.pass.json")
    bad["false_novel_rate"] = 2
    with pytest.raises(ValueError, match="fraction"):
        validate_metrics(bad)
