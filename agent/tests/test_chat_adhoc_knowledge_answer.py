"""Deterministic knowledge-only sections for synthetic chat RCA requests."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from app.knowledge import load_failure_modes
from app.masking import build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.kg_enrichment import KGContext
from app.services.pipeline import PipelineState, harness_stage, synthesize_stage
from app.services.root_cause_ranking import RankedCause
from tests.test_orchestrator import make_settings, make_target

# A non-empty knowledge catalog that never matches XID8_QUESTION -- so
# _kb_remediation_lines walks its symptom loop and falls through to the
# "no closely-matching prior knowledge" line, instead of the KGContext's own
# empty-catalog early-out (a knowledge={} dict short-circuits before that
# line is ever reached).
_UNMATCHED_KNOWLEDGE = {
    "node_kubelet_pressure": [
        {
            "symptom": "Node Disk Pressure",
            "keywords": ["diskpressure-unrelated-keyword"],
            "actions": ["Cordon or drain the node"],
        }
    ]
}

XID_QUESTION = "XID48 에러가 발생했는데 어떤 걸 해야할까요?"
XID8_QUESTION = "XID 8은 무엇이고 어떻게 조치해야 하나요?"
FAILURE_MODES_PATH = "knowledge/failure_modes.yaml"
REMOVED_HEADING_EN = "## Knowledge-Based Answer"
REMOVED_HEADING_KO = "## 지식 기반 답변"

EXPECTED_XID8_SECTIONS_KO = "\n".join(
    [
        "## 1. 문제 (Problem)",
        "",
        pipeline._chat_adhoc_knowledge_banner("ko"),
        "XID 8 — GPU stopped processing (non-fatal) · 대상 GPU 모델: "
        "A100, H100, B100, GB200 (카탈로그 적용 대상)",
        '- **운영자 질문**: "XID 8은 무엇이고 어떻게 조치해야 하나요?"',
        "",
        "## 2. 원인 (Root Cause)",
        "",
        "클러스터 직접 증거가 없으므로 아래 내용은 현재 원인 진단이 아닙니다.",
        "- **[XID 카탈로그]** 설명: GPU stopped processing",
        "- **트리거**: XID 8 카탈로그에는 트리거가 명시되어 있지 않습니다.",
        "",
        "## 3. 권장 조치 (Recommended Actions)",
        "",
        "1. **[XID 카탈로그]** RESTART_APP",
        "2. **[XID 카탈로그]** CONTACT_SUPPORT",
    ]
)


def _chat_adhoc_request(
    question: str, *, fingerprint: str = "chat-adhoc-testfp0001abcd", manual: bool = False
) -> AlertAnalysisRequest:
    # ``manual=True`` mirrors an operator manually re-analyzing a chat-adhoc
    # incident: same synthetic-alert identity (chat.go mints it once), but
    # analysis_type/analysis_request_source say "manual" instead of "chat" --
    # the trigger for THIS run, not what the alert is.
    trigger = "manual" if manual else "chat"
    return AlertAnalysisRequest(
        analysis_type=trigger,
        alert=Alert(
            status="firing",
            labels={
                "alertname": "OperatorRequestedAnalysis",
                "severity": "info",
                "source": "chat",
            },
            annotations={
                "summary": question[:160],
                "operator_prompt": question,
                "analysis_request_source": trigger,
            },
            fingerprint=fingerprint,
        ),
    )


def _make_state(request: AlertAnalysisRequest, *, settings=None, **overrides) -> PipelineState:
    settings = settings or make_settings()
    state = PipelineState(
        settings=settings,
        request=request,
        target=make_target(),
        progress=ProgressReporter(settings, run_id=""),
        masker=build_masker(()),
        collectors=[],
        kg_context=KGContext(),
        plan=InvestigationPlan(),
    )
    for key, value in overrides.items():
        setattr(state, key, value)
    return state


# Marker predicate: only the THREE alert-identity markers matter (alertname,
# source label, fingerprint prefix) -- chat.go mints them exclusively for its
# synthetic ad-hoc alert. analysis_type/analysis_request_source describe which
# button triggered THIS run, not what the alert is, and must NOT gate this.


def test_is_chat_adhoc_true_with_the_three_identity_markers() -> None:
    assert pipeline._is_chat_adhoc(_chat_adhoc_request(XID_QUESTION))


def test_is_chat_adhoc_true_for_a_manual_rerun_of_a_chat_adhoc_incident() -> None:
    # An operator manually re-analyzing a chat-adhoc incident: the backend
    # sends analysis_type="manual" and analysis_request_source="manual", but
    # the alert being re-run is still chat.go's synthetic ad-hoc alert (same
    # three identity markers). This must stay chat-adhoc -- the whole point of
    # the fix -- or the operator's own question text re-enters evidence.
    assert pipeline._is_chat_adhoc(_chat_adhoc_request(XID8_QUESTION, manual=True))


def test_is_chat_adhoc_false_for_a_real_alert() -> None:
    request = AlertAnalysisRequest(
        analysis_type="firing",
        alert=Alert(
            status="firing",
            labels={"alertname": "KubePodCrashLooping"},
            fingerprint="real-fp-1",
        ),
    )
    assert not pipeline._is_chat_adhoc(request)


def test_is_chat_adhoc_false_for_a_manual_rerun_with_operator_prompt() -> None:
    request = AlertAnalysisRequest(
        analysis_type="manual",
        alert=Alert(
            status="firing",
            labels={"alertname": "KubePodCrashLooping"},
            annotations={
                "operator_prompt": "please check CoreDNS",
                "analysis_request_source": "manual",
            },
            fingerprint="real-fp-2",
        ),
    )
    assert not pipeline._is_chat_adhoc(request)


def test_is_chat_adhoc_false_for_wrong_fingerprint() -> None:
    request = _chat_adhoc_request(XID_QUESTION, fingerprint="not-the-adhoc-prefix-0001")
    assert not pipeline._is_chat_adhoc(request)


def test_is_chat_adhoc_false_without_the_operator_requested_analysis_alertname() -> None:
    request = AlertAnalysisRequest(
        analysis_type="chat",
        alert=Alert(
            status="firing",
            labels={"alertname": "SomeOtherAlert", "source": "chat"},
            fingerprint="chat-adhoc-x",
        ),
    )
    assert not pipeline._is_chat_adhoc(request)


def test_is_chat_adhoc_false_without_the_source_chat_label() -> None:
    request = AlertAnalysisRequest(
        analysis_type="chat",
        alert=Alert(
            status="firing",
            labels={"alertname": "OperatorRequestedAnalysis"},
            fingerprint="chat-adhoc-x",
        ),
    )
    assert not pipeline._is_chat_adhoc(request)


# Seed honesty: an operator question is lookup input, never incident evidence.


def test_chat_adhoc_xid_question_mints_no_alert_signature_evidence() -> None:
    request = _chat_adhoc_request(XID_QUESTION)
    codes, matched_by_family = pipeline._asserted_alert_signatures(request)
    assert codes == []
    assert matched_by_family == {}
    assert pipeline._alert_signature_evidence_result(request, make_target()) is None
    assert "xid48" not in pipeline._alert_signature_text(request).casefold()
    assert "XID48" in pipeline._alert_text(request)
    assert "xid48" not in pipeline._observed_text([], request)


def test_chat_adhoc_xid_question_does_not_promote_gpu_hardware_error() -> None:
    request = _chat_adhoc_request(XID_QUESTION)
    codes = pipeline._xid_codes_from_results([], pipeline._alert_signature_text(request))
    assert codes == []


def test_manual_rerun_of_chat_adhoc_xid_question_mints_no_alert_signature_evidence() -> None:
    # The hole this predicate fix closes: live incident
    # INC-1786508710550925434-000001's manual re-analysis (analysis_type=
    # "manual") of "Xid 8..." previously fell out of _is_chat_adhoc, so the
    # question's own "XID 8" re-entered evidence and "confirmed" itself via
    # E77-style self-evidence. Same assertions as the chat-triggered test
    # above, but analysis_type/analysis_request_source="manual".
    request = _chat_adhoc_request(XID8_QUESTION, manual=True)
    codes, matched_by_family = pipeline._asserted_alert_signatures(request)
    assert codes == []
    assert matched_by_family == {}
    assert pipeline._alert_signature_evidence_result(request, make_target()) is None
    assert "8" not in pipeline._alert_signature_text(request)
    assert "8" in pipeline._alert_text(request)
    assert pipeline._xid_codes_from_results([], pipeline._alert_signature_text(request)) == []


def test_real_alert_xid_in_summary_is_completely_unaffected() -> None:
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "GPUXidError"},
            annotations={"summary": "NVIDIA XID 79: GPU has fallen off the bus"},
            fingerprint="real-fp-xid",
        ),
    )
    assert not pipeline._is_chat_adhoc(request)
    codes, _matched = pipeline._asserted_alert_signatures(request)
    assert codes == [79]
    assert pipeline._alert_signature_evidence_result(request, make_target()) is not None
    assert pipeline._xid_codes_from_results([], pipeline._alert_signature_text(request)) == [79]
    assert "xid 79" in pipeline._observed_text([], request)


KNOWN_ISSUE_FIXTURE = [
    {
        "issue": "Scheduler Livez Deadlock",
        "family": "runai_control_plane_error",
        "keywords": ["livez deadlock"],
        "reason": "KI-REASON a stale lock held past its lease.",
        "actions": ["KI-ACTION restart the scheduler pod."],
        "affected_version": "",
        "fixed_version": "",
        "refs": [],
    }
]

SCHEDULING_MODES = {
    "runai_scheduling_quota": [
        {
            "symptom": "Gang Or Pod-Group Not Scheduling",
            "keywords": ["gang schedul"],
            "reason": "LADDER-GANG group admission did not complete.",
            "actions": ["LADDER-GANG read the pod-grouper logs."],
        }
    ]
}

THANOS_CASE_CARD = {
    "kind": "external",
    "case_id": "enterprise_support:abc123",
    "context_class": "mitigated_context",
    "analysis_summary": "LADDER-CASE Thanos Receive exceeded a 64 GB memory limit.",
    "successful_actions": [
        {"statement": "LADDER-CASE-ACTION increase CPU request/limit.", "outcome": "mitigated"}
    ],
}


def test_structured_ladder_preserves_exact_rung_content_and_provenance() -> None:
    xid = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(_chat_adhoc_request(XID8_QUESTION)), XID8_QUESTION
        )
    )
    assert xid.match_status == "exact"
    assert xid.provenance_tags == ("xid_catalog:catalog_fallback",)
    assert "XID 8 — GPU stopped processing" in xid.problem_lines[0]
    assert "does not specify a trigger" in "\n".join(xid.cause_lines)
    assert "RESTART_APP" in "\n".join(xid.action_lines)

    question = "scheduler livez deadlock 발생했는데 어떻게 하나요?"
    issue = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(_chat_adhoc_request(question), known_issues=KNOWN_ISSUE_FIXTURE),
            question,
        )
    )
    assert issue.match_status == "exact"
    assert issue.provenance_tags == ("known_issue",)
    assert "KI-REASON" in "\n".join(issue.cause_lines)
    assert "KI-ACTION" in "\n".join(issue.action_lines)

    question = "pod is stuck: gang schedul failure on the group"
    symptom = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(_chat_adhoc_request(question), failure_modes=SCHEDULING_MODES),
            question,
        )
    )
    assert symptom.match_status == "exact"
    assert symptom.provenance_tags == ("curated_symptom:runai_scheduling_quota",)
    assert "LADDER-GANG" in "\n".join(symptom.action_lines)

    question = "아무 상관 없는 질문입니다"
    case = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(
                _chat_adhoc_request(question),
                kg_context=KGContext(case_cards=[THANOS_CASE_CARD]),
            ),
            question,
        )
    )
    assert case.match_status == "exact"
    assert case.provenance_tags == ("external_case",)
    assert "LADDER-CASE" in "\n".join(case.cause_lines)
    assert "Past Support Case" in "\n".join(case.supplementary_lines)


def test_bm25_is_nearest_only_and_is_suppressed_by_an_exact_match() -> None:
    modes = load_failure_modes(FAILURE_MODES_PATH)
    question = "작업이 선점됐어요"
    nearest = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(_chat_adhoc_request(question), failure_modes=modes), question
        )
    )
    assert nearest.match_status == "nearest"
    assert "Nearest Knowledge — Not an Exact Match" in "\n".join(
        nearest.supplementary_lines
    )

    exact_question = "scheduler livez deadlock 작업이 선점됐어요"
    exact = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(
                _chat_adhoc_request(exact_question),
                known_issues=KNOWN_ISSUE_FIXTURE,
                failure_modes=modes,
            ),
            exact_question,
        )
    )
    assert exact.match_status == "exact"
    assert not any(tag.startswith("bm25:") for tag in exact.provenance_tags)
    assert "Nearest Knowledge" not in "\n".join(exact.supplementary_lines)


def test_planner_family_leads_appear_only_without_an_exact_match() -> None:
    plan = InvestigationPlan(
        hypotheses=[{"family": "runai_scheduling_quota"}], llm_refined=True
    )
    exact_question = "scheduler livez deadlock"
    exact = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(
                _chat_adhoc_request(exact_question),
                known_issues=KNOWN_ISSUE_FIXTURE,
                failure_modes=SCHEDULING_MODES,
                plan=plan,
            ),
            exact_question,
        )
    )
    assert "Interpreted As" not in "\n".join(exact.supplementary_lines)
    assert not any(tag.startswith("planner_family:") for tag in exact.provenance_tags)

    unmatched_question = "runai 스케줄링 오류가 발생하면 어떻게 하나요?"
    unmatched = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(
                _chat_adhoc_request(unmatched_question),
                failure_modes=SCHEDULING_MODES,
                plan=plan,
            ),
            unmatched_question,
        )
    )
    assert unmatched.match_status == "none"
    assert "Interpreted As:" in "\n".join(unmatched.supplementary_lines)
    assert "planner_family:runai_scheduling_quota" in unmatched.provenance_tags


def test_no_match_is_structured_and_keeps_confirmation_pointers() -> None:
    question = "user deleted old experiment after successful completion"
    result = asyncio.run(
        pipeline._chat_adhoc_knowledge_ladder_lines(
            _make_state(
                _chat_adhoc_request(question),
                failure_modes=load_failure_modes(FAILURE_MODES_PATH),
            ),
            question,
        )
    )
    assert result == pipeline.ChatAdhocKnowledge()
    problem, cause, actions = pipeline._chat_adhoc_knowledge_section_bodies(
        _chat_adhoc_request(question), result, "en"
    )
    assert problem[0] == pipeline._chat_adhoc_knowledge_banner("en")
    assert "No matching knowledge was found in the knowledge base" in cause[-1]
    assert len(actions) == 3
    assert "error text" in actions[0]
    assert "pod" in actions[1] and "node" in actions[1]
    assert "alert name" in actions[2]


@pytest.mark.asyncio
async def test_xid8_replaces_sections_one_two_three_without_question_echo_or_family_lead() -> None:
    settings = replace(
        make_settings(), language="ko", enable_rca_output_harness=False
    )
    plan = InvestigationPlan(
        hypotheses=[{"family": "runai_scheduling_quota"}], llm_refined=True
    )
    state = _make_state(
        _chat_adhoc_request(XID8_QUESTION),
        settings=settings,
        plan=plan,
        failure_modes=SCHEDULING_MODES,
        root_cause_candidates=[RankedCause("insufficient_evidence", "low", 0.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    detail = state.response.analysis_detail
    assert EXPECTED_XID8_SECTIONS_KO in detail
    assert f"- 증상: {XID8_QUESTION}" not in detail
    assert REMOVED_HEADING_KO not in detail
    assert REMOVED_HEADING_EN not in detail
    assert "[다음으로 해석됨" not in detail
    assert "[Interpreted As" not in detail
    assert state.response.context.get("answer_mode") == "knowledge_only"
    assert state.response.root_cause_family == "insufficient_evidence"


@pytest.mark.asyncio
async def test_manual_rerun_with_zero_eligible_support_also_renders_knowledge_sections() -> None:
    # Same scenario as the chat-triggered test above, but the request is a
    # manual re-analysis (analysis_type="manual") of the same chat-adhoc
    # incident. With _is_chat_adhoc now identity-only, this must behave
    # identically to the chat-triggered run -- the knowledge sections render
    # and answer_mode is knowledge_only, regardless of which button re-ran it.
    settings = replace(make_settings(), language="ko", enable_rca_output_harness=False)
    plan = InvestigationPlan(hypotheses=[{"family": "runai_scheduling_quota"}], llm_refined=True)
    state = _make_state(
        _chat_adhoc_request(XID8_QUESTION, manual=True),
        settings=settings,
        plan=plan,
        failure_modes=SCHEDULING_MODES,
        root_cause_candidates=[RankedCause("insufficient_evidence", "low", 0.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    assert state.chat_adhoc_knowledge is not None
    detail = state.response.analysis_detail
    assert EXPECTED_XID8_SECTIONS_KO in detail
    assert state.response.context.get("answer_mode") == "knowledge_only"


@pytest.mark.asyncio
async def test_no_match_replaces_sections_and_sets_answer_mode() -> None:
    question = "user deleted old experiment after successful completion"
    settings = replace(make_settings(), enable_rca_output_harness=False)
    state = _make_state(
        _chat_adhoc_request(question),
        settings=settings,
        failure_modes=load_failure_modes(FAILURE_MODES_PATH),
        root_cause_candidates=[RankedCause("insufficient_evidence", "low", 0.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    detail = state.response.analysis_detail
    assert "## 1. Problem" in detail
    assert "## 2. Root Cause" in detail
    assert "No matching knowledge was found in the knowledge base" in detail
    assert "## 3. Recommended Actions" in detail
    assert "1. Share the exact error text" in detail
    assert REMOVED_HEADING_EN not in detail
    assert state.chat_adhoc_knowledge == pipeline.ChatAdhocKnowledge()
    assert state.response.context.get("answer_mode") == "knowledge_only"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("language", "problem_heading", "banner_fragment"),
    [
        ("en", "## 1. Problem", "No direct evidence for this question was found"),
        ("ko", "## 1. 문제 (Problem)", "클러스터에서 이 질문과 관련된 직접 증거를"),
    ],
)
async def test_knowledge_sections_survive_hard_gate_abstain_in_both_languages(
    language: str, problem_heading: str, banner_fragment: str
) -> None:
    settings = replace(make_settings(), language=language, enable_rca_output_harness=True)
    state = _make_state(
        _chat_adhoc_request(XID8_QUESTION),
        settings=settings,
        results=[],
        root_cause_candidates=[RankedCause("gpu_hardware_error", "high", 8.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    assert state.response.root_cause_family == "insufficient_evidence"
    detail = state.response.analysis_detail
    assert problem_heading in detail
    assert banner_fragment in detail
    assert "XID 8 — GPU stopped processing" in detail
    assert "RESTART_APP" in detail
    assert REMOVED_HEADING_EN not in detail
    assert REMOVED_HEADING_KO not in detail
    assert state.response.context.get("answer_mode") == "knowledge_only"


@pytest.mark.asyncio
async def test_real_alert_sections_are_untouched_and_chat_ladder_does_not_run(monkeypatch) -> None:
    async def fail_if_called(_state, _question):
        raise AssertionError("chat knowledge ladder ran for a real alert")

    monkeypatch.setattr(pipeline, "_chat_adhoc_knowledge_ladder_lines", fail_if_called)
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "KubePodCrashLooping"},
            annotations={"summary": "pod is crash looping"},
            fingerprint="real-fp-abstain",
        )
    )
    state = _make_state(
        request,
        settings=replace(make_settings(), enable_rca_output_harness=False),
        root_cause_candidates=[RankedCause("insufficient_evidence", "low", 0.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    assert state.chat_adhoc_knowledge is None
    assert "- What: pod is crash looping" in state.response.analysis_detail
    assert "answer_mode" not in state.response.context
    assert REMOVED_HEADING_EN not in state.response.analysis_detail


@pytest.mark.asyncio
async def test_chat_adhoc_with_eligible_evidence_does_not_use_knowledge_sections(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        pipeline, "_eligible_support_ids_for_output", lambda state: {"kubernetes:1"}
    )
    state = _make_state(
        _chat_adhoc_request(XID8_QUESTION),
        settings=replace(make_settings(), enable_rca_output_harness=False),
        root_cause_candidates=[RankedCause("gpu_hardware_error", "high", 9.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    assert state.chat_adhoc_knowledge is None
    assert "XID 8 — GPU stopped processing" not in state.response.analysis_detail
    assert "answer_mode" not in state.response.context


@pytest.mark.asyncio
async def test_chat_adhoc_with_eligible_evidence_appendix_is_proper_korean(
    monkeypatch,
) -> None:
    # Same "evidence turned up after all" scenario as the test above (real
    # incident INC-1786508710550925434-000001: the alertmanager XID-8 report
    # itself became eligible support evidence), but with the Knowledge Base
    # appendix enabled -- its ko no-match line used to read half-English
    # ("...closely-matching하는 사전 지식이 아직 없습니다").
    monkeypatch.setattr(
        pipeline, "_eligible_support_ids_for_output", lambda state: {"kubernetes:1"}
    )
    state = _make_state(
        _chat_adhoc_request(XID8_QUESTION),
        settings=replace(make_settings(), language="ko", enable_rca_output_harness=False),
        kg_context=KGContext(enabled=True, available=True, knowledge=_UNMATCHED_KNOWLEDGE),
        root_cause_candidates=[RankedCause("gpu_hardware_error", "high", 9.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    detail = state.response.analysis_detail
    assert "answer_mode" not in state.response.context  # not a knowledge-only run
    assert "이 증거와 밀접하게 일치하는 사전 지식은 아직 없습니다." in detail
    assert "closely-matching" not in detail


@pytest.mark.asyncio
async def test_chat_adhoc_knowledge_only_appendix_does_not_contradict_the_answer() -> None:
    # No eligible evidence at all -- a true knowledge-only run (like a chat
    # question whose cluster sweep found nothing). The Knowledge Base
    # appendix's no-match line must not read as contradicting the knowledge
    # answer already given in sections 1-3 above it.
    state = _make_state(
        _chat_adhoc_request(XID8_QUESTION),
        settings=replace(make_settings(), language="ko", enable_rca_output_harness=False),
        kg_context=KGContext(enabled=True, available=True, knowledge=_UNMATCHED_KNOWLEDGE),
        root_cause_candidates=[RankedCause("insufficient_evidence", "low", 0.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    detail = state.response.analysis_detail
    assert state.response.context.get("answer_mode") == "knowledge_only"
    assert "위 답변은 클러스터 증거가 아니라 이 질문에 대한 지식 베이스 매칭 결과로" in detail
    assert "closely-matching" not in detail
    assert "이 증거와 밀접하게 일치하는 사전 지식은 아직 없습니다." not in detail
