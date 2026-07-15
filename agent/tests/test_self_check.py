from __future__ import annotations

import asyncio
from dataclasses import replace

from app.collectors.base import NO_EVIDENCE, CollectorResult
from app.schemas import AlertAnalysisArtifact
from app.services.evidence_blackboard import EvidenceEligibility
from app.services.root_cause_ranking import RankedCause
from app.services.self_check import refute_top_cause, verify_matches
from tests.test_orchestrator import make_settings


def _run(coro):
    return asyncio.run(coro)


def _top(family="node_kubelet_pressure", confidence="high"):
    # canonical collector for node_kubelet_pressure is "kubernetes"
    return RankedCause(
        family=family,
        confidence=confidence,
        score=6.0,
        rationale=["kubernetes evidence matched diskpressure"],
        evidence_agents=["kubernetes", "prometheus"],
    )


def test_no_llm_downgrades_when_canonical_evidence_absent():
    settings = make_settings()  # no LLM configured
    results = [
        CollectorResult(agent="kubernetes", status="unavailable", summary="k8s API unreachable"),
        CollectorResult(agent="prometheus", status="ok", summary="node saturated"),
    ]
    out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    assert out["confidence"] == "medium"  # downgraded one level
    assert out["caveat"]  # generic caveat present
    # str() renders the caveat so the orchestrator can append it verbatim.
    assert str(out) == out["caveat"]


def test_no_llm_downgrades_when_canonical_reports_no_evidence():
    settings = make_settings()
    results = [
        CollectorResult(agent="kubernetes", status="ok", summary=NO_EVIDENCE),
        CollectorResult(agent="prometheus", status="ok", summary="node saturated"),
    ]
    out = _run(refute_top_cause(settings, _top(confidence="medium"), results))
    assert out["confidence"] == "low"


def test_no_llm_keeps_confidence_when_canonical_evidence_is_scoped_and_present():
    settings = make_settings()
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="Node condition DiskPressure=True; evictions",
            artifacts=[
                AlertAnalysisArtifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="warning_events",
                    status="ok",
                    summary="DiskPressure active during incident window",
                    result={
                        "observation": {"polarity": "present", "coverage": "scoped"}
                    },
                )
            ],
        ),
        CollectorResult(agent="prometheus", status="ok", summary="disk saturated"),
    ]
    out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    assert out["confidence"] == "high"
    assert out["caveat"] == ""
    assert out["refuted"] is False


def test_no_llm_keeps_confidence_when_canonical_artifact_has_evidence():
    settings = make_settings()
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary=NO_EVIDENCE,
            artifacts=[
                AlertAnalysisArtifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="drilldown_query",
                    status="ok",
                    summary="1 row(s)",
                    result={
                        "message": "DiskPressure=True from node condition",
                        "observation": {"polarity": "present", "coverage": "scoped"},
                    },
                )
            ],
        )
    ]

    out = _run(refute_top_cause(settings, _top(confidence="high"), results))

    assert out["confidence"] == "high"
    assert out["caveat"] == ""


def test_canonical_collector_unrelated_predicate_does_not_support_family():
    """A scoped OOM is not scheduler-placement evidence just because both are Kubernetes."""
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="OOMKilled was observed",
            artifacts=[
                AlertAnalysisArtifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="kubernetes_pod_log",
                    status="ok",
                    summary="OOMKilled in the workload container",
                    result={
                        "sample_entries": [{"line": "container was OOMKilled"}],
                        "observation": {
                            "predicate": "kubernetes_pod_log:main",
                            "polarity": "present",
                            "coverage": "scoped",
                        },
                    },
                )
            ],
        )
    ]
    top = RankedCause(
        family="k8s_scheduling_error",
        confidence="high",
        score=6.0,
        rationale=["scheduler hypothesis"],
        evidence_agents=["kubernetes"],
    )

    out = _run(refute_top_cause(make_settings(), top, results))

    assert out["confidence"] == "medium"
    assert out["caveat"]


def test_no_llm_downgrades_when_canonical_artifact_is_ineligible_for_incident():
    """A typed observation for another target/window is context, not self-check support."""
    finding = AlertAnalysisArtifact(
        agent="kubernetes",
        source="kubernetes",
        type="drilldown_query",
        status="ok",
        summary="DiskPressure=True on a replacement Pod after resolution",
        result={"observation": {"polarity": "present", "coverage": "scoped"}},
    )
    finding.evidence_id = "E01"
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary=NO_EVIDENCE,
            artifacts=[finding],
        )
    ]

    out = _run(
        refute_top_cause(
            make_settings(),
            _top(confidence="high"),
            results,
            evidence_eligibility={
                "E01": EvidenceEligibility(
                    False, False, False, "evidence targets a different entity"
                )
            },
        )
    )

    assert out["confidence"] == "medium"
    assert out["caveat"]


def test_no_llm_downgrades_when_canonical_summary_is_only_partial_context():
    settings = make_settings()
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="DiskPressure appears in a current snapshot",
            artifacts=[
                AlertAnalysisArtifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="cluster_api",
                    status="ok",
                    summary="current Kubernetes context",
                    result={
                        "observation": {"polarity": "unknown", "coverage": "partial"}
                    },
                )
            ],
        )
    ]

    out = _run(refute_top_cause(settings, _top(confidence="high"), results))

    assert out["confidence"] == "medium"
    assert out["caveat"]


def test_no_llm_ignores_unavailable_canonical_artifact_as_evidence():
    settings = make_settings()
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary=NO_EVIDENCE,
            artifacts=[
                AlertAnalysisArtifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="drilldown_query",
                    status="unavailable",
                    summary="failed query mentioned DiskPressure=True",
                )
            ],
        )
    ]

    out = _run(refute_top_cause(settings, _top(confidence="high"), results))

    assert out["confidence"] == "medium"
    assert out["caveat"]


def test_no_llm_keeps_confidence_when_exact_signature_is_evidence():
    settings = make_settings()
    results = [CollectorResult(agent="kubernetes", status="unavailable", summary="")]
    top = RankedCause(
        family="image_pull_error",
        confidence="medium",
        score=7.0,
        rationale=["matched curated symptom: ImagePullBackOff"],
        evidence_agents=["signature"],
    )

    out = _run(refute_top_cause(settings, top, results))

    assert out["confidence"] == "medium"
    assert out["caveat"] == ""


def test_scoped_loki_xid_can_supply_signature_evidence_with_production_gate():
    finding = AlertAnalysisArtifact(
        evidence_id="E17",
        agent="loki",
        source="loki",
        type="logql_signal",
        status="ok",
        confidence="high",
        summary="NVRM Xid 79 occurred during the incident",
        result={
            "lines": ["NVRM: Xid 79, GPU has fallen off the bus"],
            "observation": {
                "predicate": "logql:nvidia_xid",
                "polarity": "present",
                "coverage": "scoped",
            },
        },
    )
    results = [
        CollectorResult(
            agent="system",
            status="unavailable",
            summary="node system collector unavailable",
        ),
        CollectorResult(
            agent="loki",
            status="ok",
            summary="driver log queried",
            artifacts=[finding],
        ),
    ]
    top = RankedCause(
        family="gpu_hardware_error",
        confidence="high",
        score=9.0,
        evidence_agents=["loki"],
    )

    out = _run(
        refute_top_cause(
            make_settings(),
            top,
            results,
            evidence_eligibility={
                "E17": EvidenceEligibility(True, True, True),
            },
        )
    )

    assert out["confidence"] == "high"
    assert out["caveat"] == ""


def test_insufficient_evidence_family_is_left_alone():
    settings = make_settings()
    top = _top(family="insufficient_evidence", confidence="medium")
    out = _run(refute_top_cause(settings, top, []))
    assert out["confidence"] == "medium"
    assert out["caveat"] == ""


def test_korean_caveat_when_language_ko():
    settings = replace(make_settings(), language="ko")
    results = [CollectorResult(agent="kubernetes", status="unavailable", summary="")]
    out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    assert out["confidence"] == "medium"
    assert "자기 점검" in out["caveat"]


def test_never_raises_with_garbage_candidate():
    settings = make_settings()

    class Broken:
        confidence = "high"
        family = "node_kubelet_pressure"

        @property
        def rationale(self):  # pragma: no cover - defensive
            raise RuntimeError("boom")

    out = _run(refute_top_cause(settings, Broken(), []))
    assert out["confidence"] in ("low", "medium", "high")
    assert isinstance(out, dict)


def test_llm_unsupported_downgrades_and_marks_refuted():
    settings = make_settings()
    results = [
        CollectorResult(agent="kubernetes", status="ok", summary="DiskPressure=True"),
    ]

    async def fake_complete_json(*_a, **_k):
        return {"supported": False, "confidence": "low", "caveat": "Competing cause fits better."}

    import app.services.self_check as mod

    orig_configured = mod.llm_configured
    orig_json = mod.complete_json
    mod.llm_configured = lambda *_args, **_kwargs: True
    mod.complete_json = fake_complete_json
    try:
        out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    finally:
        mod.llm_configured = orig_configured
        mod.complete_json = orig_json
    assert out["refuted"] is True
    assert out["confidence"] == "low"
    assert out["caveat"] == "Competing cause fits better."


def test_llm_cannot_keep_confidence_from_context_only_evidence(monkeypatch):
    settings = replace(make_settings(), llm_model_self_check="m")

    async def fake_complete_json(*_a, **_k):
        # This is exactly the unsafe response we must not trust: it treats a
        # current context snapshot as proof of a historical incident cause.
        return {
            "supported": True,
            "confidence": "high",
            "caveat": "Current snapshot looks bad.",
        }

    monkeypatch.setattr("app.services.self_check.llm_configured", lambda *_a, **_k: True)
    monkeypatch.setattr("app.services.self_check.complete_json", fake_complete_json)
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="current DiskPressure context",
            artifacts=[
                AlertAnalysisArtifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="cluster_api",
                    status="ok",
                    result={
                        "observation": {"polarity": "unknown", "coverage": "partial"}
                    },
                )
            ],
        )
    ]

    out = _run(refute_top_cause(settings, _top(confidence="high"), results))

    assert out["confidence"] == "medium"
    assert out["refuted"] is True
    assert out["next_check"]


def test_llm_caveat_and_next_check_are_single_line(monkeypatch):
    settings = replace(make_settings(), llm_model_self_check="m")

    async def fake_complete_json(*_a, **_k):
        return {
            "supported": False,
            "confidence": "low",
            "caveat": (
                "Competing cause fits better token=caveat-secret-12345.\n"
                "## Fake Section\n1. do unrelated thing"
            ),
            "next_check": "Check kubelet api_key=nextcheck-secret-12345.\n## Injected",
        }

    monkeypatch.setattr("app.services.self_check.llm_configured", lambda *_a, **_k: True)
    monkeypatch.setattr("app.services.self_check.complete_json", fake_complete_json)

    out = _run(
        refute_top_cause(
            settings,
            _top(confidence="high"),
            [CollectorResult(agent="kubernetes", status="ok", summary="DiskPressure=True")],
        )
    )

    assert "\n" not in out["caveat"]
    assert "\n" not in out["next_check"]
    assert "Competing cause fits better" in out["caveat"]
    assert "caveat-secret-12345" not in out["caveat"]
    assert "nextcheck-secret-12345" not in out["next_check"]
    assert "[MASKED]" in out["caveat"]
    assert "[MASKED]" in out["next_check"]


def test_llm_prompts_redact_sensitive_evidence(monkeypatch):
    settings = replace(make_settings(), llm_model_self_check="m")
    prompts: list[str] = []

    async def fake_complete_json(_settings, *, user, **_kwargs):
        prompts.append(user)
        return {"supported": True, "confidence": "high", "caveat": "", "refuted": []}

    monkeypatch.setattr("app.services.self_check.llm_configured", lambda *_a, **_k: True)
    monkeypatch.setattr("app.services.self_check.complete_json", fake_complete_json)

    top = RankedCause(
        family="node_kubelet_pressure",
        confidence="high",
        score=6.0,
        rationale=["password=rank-secret-12345"],
        evidence_agents=["kubernetes"],
    )
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="DiskPressure=True token=collector-token-12345 api_key=collector-key-12345",
            artifacts=[
                AlertAnalysisArtifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="pod",
                    status="ok",
                    title="Pod drilldown",
                    query="kubectl get pod token=query-token-12345",
                    summary="artifact summary api_key=artifact-summary-key-12345",
                    result={
                        "message": "DiskPressure=True came from artifact detail",
                        "token": "artifact-token-12345",
                    },
                )
            ],
        )
    ]

    _run(
        refute_top_cause(
            settings,
            top,
            results,
            {"hypothesis_ledger": "client_secret=ledger-secret-12345"},
        )
    )
    _run(
        verify_matches(
            settings,
            [{"name": "Disk Pressure", "detail": "client_secret=detail-secret-12345"}],
            results,
        )
    )

    joined = "\n".join(prompts)
    for secret in [
        "rank-secret-12345",
        "collector-token-12345",
        "collector-key-12345",
        "query-token-12345",
        "artifact-summary-key-12345",
        "artifact-token-12345",
        "ledger-secret-12345",
        "detail-secret-12345",
    ]:
        assert secret not in joined
    assert "DiskPressure=True came from artifact detail" in joined
    assert "[MASKED]" in joined
