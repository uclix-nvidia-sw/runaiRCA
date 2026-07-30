"""KAI-Scheduler signatures must reach the right family and beat vague keywords.

The strings are the ones KAI actually emits (verified against its source); the
Pod-condition reason `BindingError` is source-verified only and has not yet been
seen on a live cluster, which is why nothing here promotes a family from it.
"""

from __future__ import annotations

import pytest

from app.knowledge import load_failure_modes, match_failure_mode_symptoms

_QUOTA = "runai_scheduling_quota"


@pytest.fixture(scope="module")
def modes() -> dict[str, list[dict]]:
    return load_failure_modes("knowledge/failure_modes.yaml")


def _top(modes: dict[str, list[dict]], text: str) -> tuple[str, str]:
    matches = match_failure_mode_symptoms(modes, text)
    assert matches, f"no symptom matched: {text!r}"
    family, symptom = matches[0]
    return family, str(symptom.get("symptom") or symptom.get("name") or "")


@pytest.mark.parametrize(
    ("log", "expected_symptom"),
    [
        # KAI commits a reclaim: the precise phrases must beat the bare
        # `reclaimed` keyword that also matches this line.
        (
            "Reclaimed resources for job runai-test1/trainer, evicting reclaimee tasks",
            "Reclaimed To Rebalance Fairshare",
        ),
        (
            "Successfully preempted for job runai-test1/trainer, preempted tasks [w-0 w-1]",
            "Preempted By Higher Priority",
        ),
        # Upstream misspelling is deliberate — keywords are literal substrings.
        (
            "Sucesfully consolidated for job runai-test1/trainer, and about to reallocate victims",
            "Consolidation Reallocated Running Workloads",
        ),
        (
            "would have placed the queue resources over quota",
            "Non-Preemptible Request Exceeds Queue Quota",
        ),
        (
            "Failed to bind pod runai-test1/trainer-0 to node dgx01: reservation not ready",
            "Bind Failed After Scheduling Decision",
        ),
        # The Pod-condition reason our widened scheduling artifact now reports.
        ("podscheduled=false reason bindingerror", "Bind Failed After Scheduling Decision"),
    ],
)
def test_kai_signature_reaches_its_symptom(
    modes: dict[str, list[dict]], log: str, expected_symptom: str
) -> None:
    family, symptom = _top(modes, log.lower())

    assert symptom == expected_symptom
    # Every one of them is a Run:ai scheduling decision, not a new family.
    assert family == _QUOTA


def test_bind_failure_suppresses_capacity_guidance(modes: dict[str, list[dict]]) -> None:
    """A decided placement that never landed is not a capacity problem."""
    matches = match_failure_mode_symptoms(
        modes, "failed to bind pod runai-test1/trainer-0 to node dgx01".lower()
    )
    _family, symptom = matches[0]

    assert symptom.get("exclusive_actions") is True
    # The fraction blocker lives outside the workload namespace, so the action
    # must not send the operator to `kubectl get pods -n <ns>` alone.
    joined = " ".join(symptom["actions"])
    assert "gpu-reservation" in joined
    assert "<ns>" in joined  # substituted with the observed namespace at render


def test_attempt_only_logs_are_not_signatures(modes: dict[str, list[dict]]) -> None:
    """A scheduler search diagnostic is not an outcome; it must not match."""
    for attempt in (
        "attempting to preempt for job runai-test1/trainer",
        "didn't find a reclaim strategy for job runai-test1/trainer",
        "can't consolidate for job runai-test1/trainer",
    ):
        for _family, symptom in match_failure_mode_symptoms(modes, attempt):
            assert symptom.get("symptom") != "Consolidation Reallocated Running Workloads"
            assert symptom.get("symptom") != "Non-Preemptible Request Exceeds Queue Quota"


def test_new_symptoms_stay_bilingual_and_in_the_closed_family_set(
    modes: dict[str, list[dict]],
) -> None:
    # All five KAI signatures, including the three that landed on entries which
    # already existed: extending their keywords makes them fire more often, so an
    # English-only remedy would now reach more Korean reports than before.
    added = {
        "Non-Preemptible Request Exceeds Queue Quota",
        "Consolidation Reallocated Running Workloads",
        "Bind Failed After Scheduling Decision",
        "Preempted By Higher Priority",
        "Reclaimed To Rebalance Fairshare",
    }
    found = {
        str(symptom.get("symptom") or symptom.get("name")): family
        for family, symptoms in modes.items()
        for symptom in symptoms
    }

    for name in added:
        assert found.get(name) == _QUOTA, f"{name} drifted out of {_QUOTA}"
    for family, symptoms in modes.items():
        for symptom in symptoms:
            if str(symptom.get("symptom") or symptom.get("name")) in added:
                assert symptom.get("reason_ko"), f"{family} entry missing reason_ko"
                assert symptom.get("actions_ko"), f"{family} entry missing actions_ko"
                assert len(symptom["actions_ko"]) == len(symptom["actions"])
