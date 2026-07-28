"""Ontology reach on evidence-free runs.

Curated keywords are written to match EVIDENCE text ("preempted by higher
priority", "failedscheduling"), so an operator QUESTION misses them in every
language -- "runai scheduling error" matches nothing even in English. These
tests pin the paths that still reach the ontology when no evidence was
collected: the target's own component identity, the alert catalog, and the
planner's family (the LLM already read the question, whatever language it was
asked in). They also pin what must NOT happen: no fabricated match, no leak
into the action sections, no match through a negated statement.
"""

from __future__ import annotations

from app.knowledge import load_failure_modes, match_failure_mode_symptoms
from app.plan import InvestigationPlan
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.general_guidance import general_guidance_lines
from app.services.root_cause_ranking import RankedCause

SCHEDULING_MODES = {
    "runai_scheduling_quota": [
        {
            "symptom": "Preempted By Higher Priority",
            "keywords": ["preempted by higher priority"],
            "actions": ["ONTOLOGY-PREEMPT check which workload preempted this one."],
        },
        {
            "symptom": "Gang Or Pod-Group Not Scheduling",
            "keywords": ["gang schedul"],
            "actions": ["ONTOLOGY-GANG read the pod-grouper logs."],
        },
    ]
}

COMPONENTS = {
    "runai-scheduler-default": {
        "purpose": "Places Run:ai workloads onto GPUs.",
        "failure_effect": "COMPONENT-EFFECT workloads stay Pending.",
        "checks": ["COMPONENT-CHECK kubectl logs -n runai deploy/runai-scheduler-default"],
    }
}

CATALOG_ALERT = {
    "alert": "NVIDIA Run:ai Agent Pull Rate Low",
    "family": "runai_control_plane_error",
    "trigger": "The runai-agent pod may be overloaded.",
    "actions": ["CATALOG-ACTION check runai-agent pod status."],
}


def guidance(query: str, **kwargs) -> str:
    return "\n".join(general_guidance_lines(query, SCHEDULING_MODES, [], **kwargs))


# --- a question reaches the ontology in ANY language, via the planner family ----


def test_question_reaches_ontology_in_any_language() -> None:
    # The planner LLM reads the operator's question and names a closed-catalog
    # family; the family name is the same regardless of the question's language.
    for question in (
        "runai 스케줄링 오류가 발생하면 어떻게 하나요?",
        "what should I do about a runai scheduling error?",
        "Run:aiのスケジューリングエラーはどう対処しますか",
    ):
        text = guidance(question, families=["runai_scheduling_quota"])
        assert "ONTOLOGY-PREEMPT" in text, question
        assert "Preempted By Higher Priority" in text, question


def test_question_alone_matches_no_keyword() -> None:
    # Why the family bridge is needed at all: the curated keywords describe
    # evidence text, so the question misses them even in English.
    assert not match_failure_mode_symptoms(SCHEDULING_MODES, "runai scheduling error")
    assert "ONTOLOGY-PREEMPT" not in guidance("runai scheduling error")


def test_exact_signature_wins_over_the_planner_family() -> None:
    # An observed signature is a stronger reason to show a symptom than the
    # planner's reading of the request, so the family fallback stays quiet.
    text = guidance(
        "pod is stuck: gang schedul failure on the group",
        families=["runai_scheduling_quota"],
    )
    assert "ONTOLOGY-GANG" in text
    assert "계열로 해석" not in text and "was interpreted as" not in text


def test_unknown_family_invents_nothing() -> None:
    # _coerce_hypotheses does not validate against the catalog, so a
    # hallucinated family must simply find no symptoms.
    text = guidance("무언가 이상합니다", families=["totally_made_up_family"])
    assert "ONTOLOGY" not in text


def test_no_match_leaves_only_the_base_guide() -> None:
    lines = general_guidance_lines("hello there", SCHEDULING_MODES, [])
    assert len(lines) == 3
    assert all(line.startswith("- ") for line in lines)


# --- negation: a question that RULES OUT a symptom must not match it ------------


def test_negated_statements_do_not_match() -> None:
    for text in (
        "gang schedul 문제가 아닙니다",
        "preempted by higher priority 는 없습니다",
        "gang schedul 은 발생하지 않습니다",
        "this is not preempted by higher priority",
    ):
        assert not match_failure_mode_symptoms(SCHEDULING_MODES, text), text


# --- component identity and alert catalog: retrieval that needs no evidence -----


def test_component_identity_reaches_the_guide() -> None:
    text = guidance(
        "무슨 일인지 모르겠어요",
        component="runai-scheduler-default",
        components=COMPONENTS,
    )
    assert "COMPONENT-EFFECT" in text
    assert "COMPONENT-CHECK" in text


def test_matched_alert_catalog_reaches_the_guide() -> None:
    text = guidance("무슨 일인지 모르겠어요", matched_alert=CATALOG_ALERT)
    assert "CATALOG-ACTION" in text
    assert "확인된 내용은 아닙니다" in text or "not a confirmed cause" in text


def test_curated_translation_is_preferred_when_present() -> None:
    modes = {
        "runai_scheduling_quota": [
            {
                "symptom": "Gang Or Pod-Group Not Scheduling",
                "keywords": ["gang schedul"],
                "actions": ["english action"],
                "actions_ko": ["한국어 조치"],
            }
        ]
    }
    text = "\n".join(general_guidance_lines("gang schedul", modes, [], language="ko"))
    assert "한국어 조치" in text and "english action" not in text


# --- the guide reaches the report, and stays out of the conclusion --------------


def _evidence_free_detail(**kwargs) -> str:
    return pipeline._detail_from(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "OperatorRequestedAnalysis"},
                annotations={"summary": "runai 스케줄링 오류가 나면 어떻게 하나요?"},
            )
        ),
        [],
        [],
        failure_modes=SCHEDULING_MODES,
        root_cause_candidates=[
            RankedCause(family="insufficient_evidence", confidence="low", score=0.0)
        ],
        eligible_support_ids=set(),
        **kwargs,
    )


def test_plan_families_reach_the_rendered_report() -> None:
    detail = _evidence_free_detail(
        plan=InvestigationPlan(
            hypotheses=[{"family": "runai_scheduling_quota"}], llm_refined=True
        )
    )
    assert "ONTOLOGY-PREEMPT" in detail
    # ... and only below the conclusion, never as a recommended action.
    actions = detail.split("## 3. Recommended Actions", 1)[1].split("## Appendix", 1)[0]
    assert "ONTOLOGY-PREEMPT" not in actions


def test_deterministic_plan_order_is_not_presented_as_an_interpretation() -> None:
    # Without the planner LLM the family order comes from the alert NAME only.
    # For a label-less operator request that leads with node_kubelet_pressure,
    # which says nothing about what was actually asked.
    detail = _evidence_free_detail(
        plan=InvestigationPlan(
            hypotheses=[
                {"family": "node_kubelet_pressure"},
                {"family": "runai_scheduling_quota"},
            ]
        )
    )
    assert "ONTOLOGY-PREEMPT" not in detail
    assert "해석되었습니다" not in detail and "was interpreted as" not in detail


def test_korean_question_reaches_scheduling_ontology_through_the_planner(monkeypatch) -> None:
    """The whole chain the operator actually hits.

    A Korean question with no target labels -> planner LLM names a catalog
    family -> the evidence-free report carries that family's curated symptoms.
    """
    import asyncio

    from app.collectors.base import resolve_target
    from app.services import planner
    from tests.test_orchestrator import make_settings

    async def fake_complete_json(*_args, **_kwargs):
        # The model answers with a closed-catalog family regardless of the
        # question's language; reason/narrative may be localized.
        return {
            "focus": "Run:ai 스케줄러",
            "hypotheses": [{"family": "runai_scheduling_quota", "reason": "스케줄링 질문"}],
            "strategy": "targeted",
            "narrative": "스케줄러 결정을 먼저 확인",
        }

    monkeypatch.setattr(planner, "complete_json", fake_complete_json)
    monkeypatch.setattr(planner, "llm_configured", lambda *_a, **_k: True)

    question = "runai 스케줄링 오류가 발생하면 어떻게 확인해야 하나요?"
    labels = {"alertname": "OperatorRequestedAnalysis", "severity": "info", "source": "chat"}
    annotations = {"summary": question, "operator_prompt": question}
    alert = Alert(status="firing", labels=labels, annotations=annotations)
    plan = asyncio.run(
        planner.plan_investigation(
            make_settings(), resolve_target(labels, annotations), alert, {}, [], []
        )
    )
    assert plan.llm_refined is True
    assert plan.hypotheses[0]["family"] == "runai_scheduling_quota"

    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=alert),
        [],
        [],
        failure_modes=load_failure_modes("knowledge/failure_modes.yaml"),
        root_cause_candidates=[
            RankedCause(family="insufficient_evidence", confidence="low", score=0.0)
        ],
        eligible_support_ids=set(),
        language="ko",
        plan=plan,
    )
    guide = detail.split("일반 점검 가이드", 1)[1]
    assert "Preempted By Higher Priority" in guide
    assert "확인된 원인이 아니라" in guide


def test_deterministic_planner_leads_with_a_default_for_a_bare_request() -> None:
    # Pins the behaviour the guard above exists for: this is a real plan, and
    # its first family is unrelated to any question the operator may have asked.
    import asyncio

    from app.collectors.base import resolve_target
    from app.services.planner import plan_investigation
    from tests.test_orchestrator import make_settings

    labels = {"alertname": "OperatorRequestedAnalysis", "severity": "info"}
    annotations = {"summary": "runai 스케줄링 오류", "operator_prompt": "runai 스케줄링 오류"}
    plan = asyncio.run(
        plan_investigation(
            make_settings(),
            resolve_target(labels, annotations),
            Alert(status="firing", labels=labels, annotations=annotations),
            {},
            [],
            [],
        )
    )
    assert plan.llm_refined is False
    assert plan.hypotheses[0]["family"] != "runai_scheduling_quota"


def test_component_and_catalog_reach_the_rendered_report() -> None:
    detail = _evidence_free_detail(
        plan=InvestigationPlan(
            component="runai-scheduler-default", matched_alert=CATALOG_ALERT
        ),
        components=COMPONENTS,
    )
    assert "COMPONENT-CHECK" in detail
    assert "CATALOG-ACTION" in detail
    actions = detail.split("## 3. Recommended Actions", 1)[1].split("## Appendix", 1)[0]
    assert "COMPONENT-CHECK" not in actions and "CATALOG-ACTION" not in actions


def test_supported_run_gets_no_general_guidance() -> None:
    detail = pipeline._detail_from(
        AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericAlert"}),
        ),
        [],
        [],
        failure_modes=SCHEDULING_MODES,
        root_cause_candidates=[
            RankedCause(family="runai_scheduling_quota", confidence="high", score=9.0)
        ],
        eligible_support_ids={"kubernetes:1"},
        plan=InvestigationPlan(hypotheses=[{"family": "runai_scheduling_quota"}]),
    )
    assert "General Troubleshooting Guidance" not in detail
    assert "일반 점검 가이드" not in detail


# --- the guide survives a harness abstain ---------------------------------------


def test_general_guidance_block_is_extracted_and_reappended() -> None:
    detail = (
        "# Report\n\n## 1. Problem\n\nx\n\n"
        "## General Troubleshooting Guidance (Not a Current RCA Conclusion)\n\n"
        "- CARRIED line\n"
    )
    block = pipeline._general_guidance_block(detail, "en")
    assert block.startswith("## General Troubleshooting Guidance")
    assert "CARRIED line" in block
    # abstain() replaces the document; re-appending must keep the guide intact.
    rewritten = pipeline._append_general_guidance("## Assessment\n\nabstained.", block)
    assert "CARRIED line" in rewritten
    assert rewritten.index("## Assessment") < rewritten.index("## General Troubleshooting")


def test_general_guidance_block_absent_returns_empty() -> None:
    assert pipeline._general_guidance_block("## 1. Problem\n\nx", "ko") == ""


def test_abstain_builds_a_guide_when_the_report_never_had_one() -> None:
    # A gated run WITH eligible evidence carries cause-specific sections and no
    # guide; abstain() replaces everything with the stub. The fallback must
    # build the guide from plan/knowledge state — the live INC-1785128597 case
    # ended as a bare 318-char stub without it.
    from types import SimpleNamespace

    from tests.test_orchestrator import make_settings

    settings = make_settings()
    state = SimpleNamespace(
        settings=settings,
        plan=InvestigationPlan(
            hypotheses=[{"family": "runai_scheduling_quota"}], llm_refined=True
        ),
        request=AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "OperatorRequestedAnalysis", "source": "chat"},
                annotations={"summary": "Thanos Receive 가 OOMKilled 반복"},
            )
        ),
        failure_modes=load_failure_modes("knowledge/failure_modes.yaml"),
        known_issues=[],
        masker=None,
    )
    block = pipeline._abstain_guidance_block(state, "ko")
    assert block.startswith("## 일반 점검 가이드")
    assert "결론이 아닙니다" in block or "결론 아님" in block


def test_general_guidance_block_finds_the_other_language() -> None:
    # A stored report may have been written under a different language setting.
    korean = "## 일반 점검 가이드 (현재 RCA 결론 아님)\n\n- 한 줄"
    assert pipeline._general_guidance_block(korean, "en").startswith("## 일반 점검 가이드")


# --- the shipped ontology really carries the scheduling knowledge ----------------


def test_shipped_scheduling_family_has_actionable_symptoms() -> None:
    modes = load_failure_modes("knowledge/failure_modes.yaml")
    symptoms = modes.get("runai_scheduling_quota") or []
    assert len(symptoms) >= 5
    assert all(symptom.get("actions") for symptom in symptoms)
    text = "\n".join(
        general_guidance_lines(
            "스케줄링 문제요", modes, [], families=["runai_scheduling_quota"]
        )
    )
    assert "Preempted By Higher Priority" in text


def test_shipped_quota_guidance_names_the_scheduler_decision_and_priority_comparison() -> None:
    modes = load_failure_modes("knowledge/failure_modes.yaml")
    text = "\n".join(
        general_guidance_lines(
            "project GPU quota changed",
            modes,
            [],
            language="ko",
            families=["runai_scheduling_quota"],
        )
    )
    assert "spec.schedulerName" in text
    assert "피해 workload" in text
    assert "deserved quota" in text
