"""Every catalogued diagnostic signature must survive ranking and the harness."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.knowledge import (
    load_failure_modes,
    load_runai_known_issues,
    match_failure_mode_symptoms,
    match_runai_known_issues,
)
from app.schemas import AlertAnalysisResponse
from app.services.harness import apply_trace, assign_evidence_ids, evaluate
from app.services.pipeline import (
    _DISPOSITIVE_TYPED_REASONS,
    _curated_symptom_signature_support,
    _dispositive_typed_state,
    _known_issue_signature_support,
    _observed_text,
    _promote_signature_cause,
    _xid_codes_from_results,
)
from app.services.root_cause_ranking import (
    _K8S_CONTAINER_REASON_FAMILY,
    FAMILIES,
    rank_root_cause_candidates,
)

ROOT = Path(__file__).parents[1]
FAMILY_ENTRIES = yaml.safe_load((ROOT / "knowledge/families.yaml").read_text())
XID_CODES = [entry["code"] for entry in yaml.safe_load((ROOT / "knowledge/xid_catalog.yaml").read_text())["xids"]]
FAILURE_MODES = load_failure_modes("knowledge/failure_modes.yaml")
KNOWN_ISSUES = load_runai_known_issues("knowledge/runai_known_issues.yaml")


@dataclass(frozen=True)
class Case:
    label: str
    family: str
    signal: str
    agent: str
    kind: str = "signal"


def _cases() -> list[Case]:
    keyword_counts = {
        keyword: sum(keyword in entry["keywords"] for entry in FAMILY_ENTRIES)
        for entry in FAMILY_ENTRIES
        for keyword in entry["keywords"]
    }
    cases = [
        Case(
            f"family:{entry['family']}", entry["family"],
            min(entry["keywords"], key=lambda keyword: (keyword_counts[keyword], -len(keyword))),
            entry["canonical_agent"],
        )
        for entry in FAMILY_ENTRIES
    ]
    typed_reasons = {
        reason.casefold(): (family, reason)
        for family, reasons in _DISPOSITIVE_TYPED_REASONS.items()
        for reason in reasons
    }
    for reason, family in _K8S_CONTAINER_REASON_FAMILY.items():
        if reason in {"unschedulable", "schedulinggated"} or reason in typed_reasons:
            continue
        typed_reasons[reason] = (
            family,
            {
                "containercannotrun": "ContainerCannotRun",
                "imageinspecterror": "ImageInspectError",
                "poststarthookerror": "PostStartHookError",
            }[reason],
        )
    cases.extend(
        Case(f"typed:{reason}", family, signal, "kubernetes", "container")
        for reason, (family, signal) in sorted(typed_reasons.items())
    )
    cases.extend(
        Case(f"scheduling:{reason}", "k8s_scheduling_error", reason, "kubernetes", "scheduling")
        for reason in ("Unschedulable", "SchedulingGated")
    )
    cases.extend(
        Case(
            f"symptom:{family}:{symptom['symptom']}",
            family,
            (
                " ".join(symptom["keywords"][:2])
                if len(symptom["keywords"][0]) < 8 and symptom["keywords"][0].isalnum()
                else symptom["keywords"][1]
                if symptom["keywords"][0] == "sxid"
                else symptom["keywords"][0]
            )
            + (" ImagePullBackOff" if family == "image_pull_error" else ""),
            next(entry["canonical_agent"] for entry in FAMILY_ENTRIES if entry["family"] == family),
            "symptom",
        )
        for family, symptoms in FAILURE_MODES.items()
        for symptom in symptoms
    )
    cases.extend(Case(f"xid:{code}", "gpu_hardware_error", f"NVRM: Xid {code}", "system", "xid") for code in XID_CODES)
    seen_known_families: set[str] = set()
    for issue in KNOWN_ISSUES:
        family = str(issue["family"])
        if family not in seen_known_families:
            seen_known_families.add(family)
            cases.append(Case(f"known:{family}", family, " ".join(issue["keywords"]), "loki", "known"))
    return cases


CASES = _cases()


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="test", project="project", queue="queue", namespace="default",
        workload_name="trainer", workload_type="Training", runai_workload_id="workload",
        node="node-1", pod="trainer-0", severity="warning", alert_name="KubePodNotReady",
    )


def _support(case: Case):
    observation = {
        "predicate": f"fixture:{case.kind}", "polarity": "present", "coverage": "scoped",
        "target_identity_verified": True,
        "observed_entity": {"kind": "pod", "name": "trainer-0", "namespace": "default"},
    }
    result: dict[str, object] = {"observation": observation}
    artifact_type = "fixture_signal"
    if case.kind == "container":
        observation["container_reason"] = case.signal
        artifact_type = "kubernetes_container_lifecycle"
        result["containers"] = [{"name": "main", "state": {"phase": "waiting", "reason": case.signal}}]
    elif case.kind == "scheduling":
        observation["scheduling_reason"] = case.signal
        artifact_type = "kubernetes_pod_scheduling"
        result["condition"] = {"type": "PodScheduled", "status": "False", "reason": case.signal}
    elif case.agent == "kubernetes":
        artifact_type = "kubernetes_pod_log"
        result["sample_entries"] = [{"line": case.signal}]
    else:
        result["lines"] = [case.signal]
    return artifact(
        agent=case.agent, source=case.agent, type=artifact_type, status="ok", confidence="high",
        summary=case.signal, result=result, highlights=[case.signal],
    )


def _noise(agent: str):
    return artifact(
        agent=agent, source=agent, type="fixture_noise", status="ok", confidence="low",
        summary="neutral telemetry summary", result={"observation": {"predicate": "fixture:noise", "polarity": "unknown", "coverage": "partial"}},
    )


def _results(case: Case) -> list[CollectorResult]:
    return [
        CollectorResult(agent=case.agent, status="ok", summary=case.signal, artifacts=[_support(case)]),
        CollectorResult(agent="loki", status="ok", summary="neutral", artifacts=[_noise("loki")]),
        CollectorResult(agent="prometheus", status="ok", summary="neutral", artifacts=[_noise("prometheus")]),
    ]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.label)
def test_every_catalogued_signature_survives_full_decision_path(case: Case) -> None:
    results = _results(case)
    assign_evidence_ids(results)
    eligible = {item.evidence_id for result in results for item in result.artifacts if item.evidence_id}
    candidates = rank_root_cause_candidates(
        _target(), results, eligible_evidence_ids=eligible,
        lifecycle={"active": True, "components": ["fixture"]} if case.family == "platform_lifecycle_change" else None,
    )
    observed = _observed_text(results, eligible_support_ids=eligible)
    known_matches = match_runai_known_issues(KNOWN_ISSUES, observed)
    symptom_matches = match_failure_mode_symptoms(FAILURE_MODES, observed)
    candidates = _promote_signature_cause(
        candidates,
        _xid_codes_from_results(results, eligible_support_ids=eligible) if case.kind == "xid" else [],
        known_matches,
        symptom_matches,
        evidence_text=observed,
        known_issue_support=_known_issue_signature_support(results, known_matches, eligible),
        symptom_support=_curated_symptom_signature_support(results, symptom_matches, eligible),
        typed_state=_dispositive_typed_state(results, eligible),
    )
    top = candidates[0]
    response = AlertAnalysisResponse(
        status="ok", thread_ts="", analysis=f"## Root Cause\n\n{case.label}",
        analysis_summary=case.label, analysis_detail=f"## Root Cause\n\n{case.label}",
        analysis_type="firing", analysis_quality="medium", root_cause_family=top.family,
        missing_data=[], warnings=[], capabilities={}, context={}, artifacts=[],
    )
    verdict = evaluate(response, results, candidates, known_issues=KNOWN_ISSUES, generic_state_alert=True)
    if verdict.failed_gates:
        apply_trace(response, verdict)
        verdict = evaluate(response, results, candidates, known_issues=KNOWN_ISSUES, generic_state_alert=True)
    assert top.family == case.family, f"ranked {top.family}; expected {case.family}"
    assert not verdict.failed_gates, f"harness gate: {verdict.failed_gates}"
    assert verdict.claims[0]["supporting_evidence"], "empty supporting evidence"


def test_sweep_enumerates_the_closed_catalog() -> None:
    labels = {case.label for case in CASES}
    assert {case.family for case in CASES if case.kind == "signal"} == set(FAMILIES)
    assert {case.signal for case in CASES if case.kind == "xid"} == {f"NVRM: Xid {code}" for code in XID_CODES}
    assert all(f"symptom:{family}:{symptom['symptom']}" in labels for family, symptoms in FAILURE_MODES.items() for symptom in symptoms)
