"""Knowledge-grounded answers for chat-adhoc operator questions.

When an operator presses the chat RCA button with a general knowledge
question ("XID48 에러가 발생했는데 어떤 걸 해야할까요?"), the backend mints a
synthetic alert (chat.go: alertname OperatorRequestedAnalysis, labels
source=chat, fingerprint "chat-adhoc-..."). The cluster sweep finds nothing
and the run abstains -- but the question itself should still get a
deterministic, clearly-bannered knowledge answer, assembled from the same
catalogs/ontology every other report section already draws from (no LLM
call). These tests cover, in order:

1. ``_is_chat_adhoc`` identifies ONLY that synthetic alert.
2. Seed-honesty: a question containing an XID must not mint alert_signature
   evidence or promote a cause, in either direction (chat-adhoc vs. a real
   alert whose OWN text names an XID, which must be completely unaffected).
3. The deterministic ladder (XID catalog -> known issue -> curated symptom ->
   external case -> qualified BM25 -> planner family -> none).
4. The rendered report section: present (EN/KO) for a chat-adhoc run with no
   evidence, absent for a real alert or a chat-adhoc run WITH evidence, and
   surviving a harness abstain together with ``answer_mode``.
"""

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

XID_QUESTION = "XID48 에러가 발생했는데 어떤 걸 해야할까요?"
FAILURE_MODES_PATH = "knowledge/failure_modes.yaml"


def _chat_adhoc_request(
    question: str, *, fingerprint: str = "chat-adhoc-testfp0001abcd"
) -> AlertAnalysisRequest:
    """The synthetic alert chat.go mints for a general question (see chat.go
    handleChat / requestAnalysisRun): both markers of "this came from chat"
    are set, matching production (AnalysisType AND the annotation)."""
    return AlertAnalysisRequest(
        analysis_type="chat",
        alert=Alert(
            status="firing",
            labels={"alertname": "OperatorRequestedAnalysis", "severity": "info", "source": "chat"},
            annotations={
                "summary": question[:160],
                "operator_prompt": question,
                "analysis_request_source": "chat",
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


# --- 1. _is_chat_adhoc: true only with all four markers ---------------------


def test_is_chat_adhoc_true_with_all_four_markers() -> None:
    assert pipeline._is_chat_adhoc(_chat_adhoc_request(XID_QUESTION))


def test_is_chat_adhoc_false_for_a_real_alert() -> None:
    request = AlertAnalysisRequest(
        analysis_type="firing",
        alert=Alert(
            status="firing", labels={"alertname": "KubePodCrashLooping"}, fingerprint="real-fp-1"
        ),
    )
    assert not pipeline._is_chat_adhoc(request)


def test_is_chat_adhoc_false_for_a_manual_rerun_with_operator_prompt() -> None:
    # A manual re-analysis of a REAL alert can also carry operator_prompt --
    # must not be mistaken for the synthetic ad-hoc alert.
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


# --- 2. Seed-honesty regression, both directions -----------------------------


def test_chat_adhoc_xid_question_mints_no_alert_signature_evidence() -> None:
    request = _chat_adhoc_request(XID_QUESTION)
    codes, matched_by_family = pipeline._asserted_alert_signatures(request)
    assert codes == []
    assert matched_by_family == {}
    assert pipeline._alert_signature_evidence_result(request, make_target()) is None
    assert "xid48" not in pipeline._alert_signature_text(request).casefold()
    # Investigation ordering must still see the question in full.
    assert "XID48" in pipeline._alert_text(request)
    assert "xid48" not in pipeline._observed_text([], request)


def test_chat_adhoc_xid_question_does_not_promote_gpu_hardware_error() -> None:
    request = _chat_adhoc_request(XID_QUESTION)
    codes = pipeline._xid_codes_from_results([], pipeline._alert_signature_text(request))
    assert codes == []


def test_real_alert_xid_in_summary_is_completely_unaffected() -> None:
    """The exact regression this fix must not cause: a real alert whose own
    Alertmanager-authored summary names an XID keeps behaving as before."""
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


# --- 3. Deterministic ladder --------------------------------------------------


def test_ladder_xid_question_renders_the_catalog_entry_with_provenance() -> None:
    state = _make_state(_chat_adhoc_request(XID_QUESTION))

    text = "\n".join(asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, XID_QUESTION)))
    assert "[XID Catalog]" in text
    assert "XID 48" in text
    assert "Double Bit ECC Error" in text


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


def test_ladder_known_issue_phrase_renders_that_subsection() -> None:
    question = "scheduler livez deadlock 발생했는데 어떻게 하나요?"
    state = _make_state(_chat_adhoc_request(question), known_issues=KNOWN_ISSUE_FIXTURE)

    text = "\n".join(asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, question)))
    assert "[Known Issue]" in text
    assert "Scheduler Livez Deadlock" in text
    assert "KI-ACTION restart the scheduler pod." in text


SCHEDULING_MODES = {
    "runai_scheduling_quota": [
        {
            "symptom": "Gang Or Pod-Group Not Scheduling",
            "keywords": ["gang schedul"],
            "actions": ["LADDER-GANG read the pod-grouper logs."],
        }
    ]
}


def test_ladder_curated_symptom_exact_match_renders_that_subsection() -> None:
    question = "pod is stuck: gang schedul failure on the group"
    state = _make_state(_chat_adhoc_request(question), failure_modes=SCHEDULING_MODES)

    text = "\n".join(asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, question)))
    assert "[Curated Symptom]" in text
    assert "Gang Or Pod-Group Not Scheduling" in text
    assert "LADDER-GANG" in text


THANOS_CASE_CARD = {
    "kind": "external",
    "case_id": "enterprise_support:abc123",
    "context_class": "mitigated_context",
    "analysis_summary": "LADDER-CASE Thanos Receive repeatedly exceeded a 64 GB memory limit.",
    "successful_actions": [
        {"statement": "LADDER-CASE-ACTION increase CPU request/limit.", "outcome": "mitigated"}
    ],
}


def test_ladder_external_case_renders_as_a_past_support_case() -> None:
    question = "아무 상관 없는 질문입니다"
    state = _make_state(
        _chat_adhoc_request(question), kg_context=KGContext(case_cards=[THANOS_CASE_CARD])
    )

    text = "\n".join(asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, question)))
    assert "[Past Support Case]" in text
    assert "LADDER-CASE" in text


def test_ladder_bm25_only_fires_when_exact_matches_are_all_empty() -> None:
    # "작업이 선점됐어요" bridges to "Preempted By Higher Priority" only through
    # the Korean-stem BM25 fallback (app.bm25) -- no curated keyword substring-
    # matches it (see test_bm25.py).
    question = "작업이 선점됐어요"
    state = _make_state(
        _chat_adhoc_request(question), failure_modes=load_failure_modes(FAILURE_MODES_PATH)
    )

    text = "\n".join(asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, question)))
    assert "[Nearest Knowledge — Not an Exact Match]" in text
    assert "Preempted By Higher Priority" in text


def test_ladder_bm25_is_suppressed_when_a_known_issue_already_matched() -> None:
    # Same bm25-qualifying phrase as above, but the question ALSO carries an
    # exact known-issue hit -- e (bm25) must stay silent once a-d found
    # anything at all.
    question = "scheduler livez deadlock 작업이 선점됐어요"
    state = _make_state(
        _chat_adhoc_request(question),
        known_issues=KNOWN_ISSUE_FIXTURE,
        failure_modes=load_failure_modes(FAILURE_MODES_PATH),
    )

    text = "\n".join(asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, question)))
    assert "[Known Issue]" in text
    assert "Nearest Knowledge" not in text
    assert "bm25" not in text.lower()


def test_ladder_planner_family_is_a_supplementary_interpreted_as_lead() -> None:
    question = "runai 스케줄링 오류가 발생하면 어떻게 하나요?"
    state = _make_state(
        _chat_adhoc_request(question),
        failure_modes=SCHEDULING_MODES,
        plan=InvestigationPlan(hypotheses=[{"family": "runai_scheduling_quota"}], llm_refined=True),
    )

    text = "\n".join(asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, question)))
    assert "[Interpreted As:" in text
    assert "Gang Or Pod-Group Not Scheduling" in text


def test_ladder_no_match_returns_nothing_and_the_block_shows_no_bm25_leakage() -> None:
    # A benign, generic sentence that qualifies for nothing in the shipped
    # catalog (pinned in test_bm25.py's ignores_generic_log_language).
    question = "user deleted old experiment after successful completion"
    state = _make_state(
        _chat_adhoc_request(question), failure_modes=load_failure_modes(FAILURE_MODES_PATH)
    )

    lines = asyncio.run(pipeline._chat_adhoc_knowledge_ladder_lines(state, question))
    assert lines == []

    block = asyncio.run(pipeline._build_chat_adhoc_knowledge_block(state, "en"))
    assert "No matching knowledge was found in the knowledge base" in block
    assert "Nearest Knowledge" not in block
    assert "bm25" not in block.lower()
    # 2-3 deterministic pointers on what detail would help.
    assert "error text" in block.lower() or "log message" in block.lower()
    assert "pod" in block.lower() and "node" in block.lower()
    assert "alert" in block.lower()


def test_no_match_lines_are_localized_in_korean() -> None:
    lines = pipeline._chat_adhoc_knowledge_no_match_lines(True)
    text = "\n".join(lines)
    assert text.startswith("질문과 관련된 지식을 지식 베이스에서 찾지 못했습니다.")
    assert any(line.startswith("- ") for line in lines[1:])


# --- 4. Report section: presence, banners, carry, answer_mode ----------------


def test_extract_chat_adhoc_knowledge_block_bounds_at_the_next_heading() -> None:
    detail = (
        "# Report\n\n## 2. Root Cause\n\nx\n\n"
        f"{pipeline._chat_adhoc_knowledge_heading('en')}\n\n"
        "- CARRIED line\n\n"
        "## Appendix\n\nmore stuff that must not leak in\n"
    )
    block = pipeline._extract_chat_adhoc_knowledge_block(detail, "en")
    assert block.startswith(pipeline._chat_adhoc_knowledge_heading("en"))
    assert "CARRIED line" in block
    assert "Appendix" not in block
    assert "must not leak in" not in block


def test_extract_chat_adhoc_knowledge_block_absent_returns_empty() -> None:
    assert pipeline._extract_chat_adhoc_knowledge_block("## 1. Problem\n\nx", "en") == ""


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("language", "banner_fragment"),
    [
        ("en", "No direct evidence for this question was found in the cluster"),
        ("ko", "클러스터에서 이 질문과 관련된 직접 증거를 찾지 못했습니다"),
    ],
)
async def test_knowledge_section_survives_a_chat_adhoc_harness_abstain(
    language: str, banner_fragment: str
) -> None:
    settings = replace(make_settings(), language=language, enable_rca_output_harness=True)
    request = _chat_adhoc_request(XID_QUESTION)
    state = _make_state(
        request,
        settings=settings,
        results=[],
        # A high-confidence claim with zero supporting artifacts fails a hard
        # harness gate (missing_evidence_trace / unsupported_high_confidence),
        # forcing abstain() -- matching test_harness.py's own pattern.
        root_cause_candidates=[RankedCause("gpu_hardware_error", "high", 8.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    # Hard product constraint: verdict semantics are untouched.
    assert state.response.root_cause_family == "insufficient_evidence"
    detail = state.response.analysis_detail
    assert pipeline._chat_adhoc_knowledge_heading(language) in detail
    assert banner_fragment in detail
    assert "XID 48" in detail
    assert state.response.context.get("answer_mode") == "knowledge_only"


@pytest.mark.asyncio
async def test_knowledge_section_absent_for_a_real_alert_abstain() -> None:
    settings = replace(make_settings(), enable_rca_output_harness=True)
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "KubePodCrashLooping"},
            fingerprint="real-fp-abstain",
        )
    )
    state = _make_state(
        request,
        settings=settings,
        results=[],
        root_cause_candidates=[RankedCause("gpu_hardware_error", "high", 8.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    assert state.response.root_cause_family == "insufficient_evidence"
    assert pipeline._chat_adhoc_knowledge_heading("en") not in state.response.analysis_detail
    assert "answer_mode" not in state.response.context


@pytest.mark.asyncio
async def test_knowledge_section_absent_for_chat_adhoc_run_with_real_evidence(monkeypatch) -> None:
    # Force the "cluster sweep found something eligible" branch without
    # reconstructing the full blackboard/eligibility machinery -- the gate
    # this test pins is _is_chat_adhoc(...) and eligible_support_ids == set().
    monkeypatch.setattr(
        pipeline, "_eligible_support_ids_for_output", lambda state: {"kubernetes:1"}
    )
    settings = make_settings()
    request = _chat_adhoc_request(XID_QUESTION)
    state = _make_state(
        request,
        settings=settings,
        results=[],
        root_cause_candidates=[RankedCause("gpu_hardware_error", "high", 9.0)],
    )

    await synthesize_stage(state)

    assert pipeline._chat_adhoc_knowledge_heading("en") not in state.detail


@pytest.mark.asyncio
async def test_knowledge_section_present_even_when_the_harness_is_disabled() -> None:
    settings = replace(make_settings(), enable_rca_output_harness=False)
    request = _chat_adhoc_request(XID_QUESTION)
    state = _make_state(
        request,
        settings=settings,
        results=[],
        root_cause_candidates=[RankedCause("insufficient_evidence", "low", 0.0)],
    )

    await synthesize_stage(state)
    await harness_stage(state)

    assert state.response is not None
    assert pipeline._chat_adhoc_knowledge_heading("en") in state.response.analysis_detail
    assert state.response.context.get("answer_mode") == "knowledge_only"
