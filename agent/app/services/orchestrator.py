from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import TypeVar
from uuid import uuid4

from pydantic import BaseModel

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, resolve_target
from app.collectors.http_json import post_json
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.collectors.system import SystemCollector
from app.config import Settings
from app.knowledge import (
    load_failure_modes,
    load_runai_known_issues,
    load_troubleshooting_cases,
    match_failure_mode_symptoms,
    match_runai_known_issues,
)
from app.llm import complete, complete_json, llm_configured
from app.masking import Masker, build_masker
from app.plan import InvestigationPlan
from app.prompts import agent_role_coverage_lines, load_agent_souls
from app.schemas import (
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    ChatRequest,
    ChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
)
from app.services.kg_enrichment import GraphRemediation, enrich, graph_remediation
from app.services.planner import plan_investigation
from app.services.root_cause_ranking import RankedCause, rank_root_cause_candidates

_log = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)


class NemoWorkflowRunner:
    """Optional bridge to NeMo Agent Toolkit's `nat` CLI.

    The local collector orchestrator remains the default so the service is useful
    without external credentials. This runner is intentionally isolated: when it
    fails, the service falls back to deterministic synthesis.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._masker = _build_settings_masker(settings)

    def enabled(self) -> bool:
        return self._settings.enable_nat_runtime

    async def run(self, payload: dict[str, object]) -> str | None:
        if not self.enabled():
            return None

        config_file = self._settings.nat_config_file
        try:
            config_file = self._materialize_config_file()
            proc = await asyncio.create_subprocess_exec(
                "nat",
                "run",
                "--config_file",
                config_file,
                "--input",
                json.dumps(self._masker.mask_object(payload), sort_keys=True),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            nat_timeout = self._settings.nat_timeout_seconds
            try:
                if nat_timeout and nat_timeout > 0:
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=nat_timeout
                    )
                else:  # 0 = no timeout: let the agent workflow run to completion
                    stdout, _ = await proc.communicate()
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return None
            if proc.returncode != 0:
                return None
            text = stdout.decode("utf-8", errors="replace").strip()
            result = _extract_nat_result(text)
            return self._masker.mask_text(result) if result else None
        finally:
            self._cleanup_materialized_config(config_file)

    def _materialize_config_file(self) -> str:
        replacements = {
            "http://localhost:9901/mcp": self._settings.prometheus_mcp_url,
            "http://localhost:9902/mcp": self._settings.loki_mcp_url,
            "__RUNAI_RCA_LLM_BASE_URL__": self._settings.llm_base_url,
            "__RUNAI_RCA_LLM_MODEL__": self._settings.llm_model,
            "__RUNAI_RCA_LLM_API_KEY__": self._settings.llm_api_key,
            # NAT's litellm config wants a positive number; our "unlimited" (0)
            # becomes a very large timeout so the sub-agent isn't cut off either.
            "__RUNAI_RCA_LLM_REQUEST_TIMEOUT_SECONDS__": str(
                self._settings.llm_request_timeout_seconds or 86400
            ),
        }
        replacements = {old: new for old, new in replacements.items() if new}
        if not replacements:
            return self._settings.nat_config_file

        try:
            source = Path(self._settings.nat_config_file)
            text = source.read_text(encoding="utf-8")
        except OSError:
            return self._settings.nat_config_file

        rendered = text
        for old, new in replacements.items():
            rendered = rendered.replace(old, new)
        if rendered == text:
            return self._settings.nat_config_file
        if "__RUNAI_RCA_LLM" in rendered:
            return self._settings.nat_config_file

        fd, target_name = tempfile.mkstemp(
            prefix="runai-rca-nat-workflow-", suffix=".yml"
        )
        target = Path(target_name)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(rendered)
        os.chmod(target, 0o600)
        return target_name

    def _cleanup_materialized_config(self, config_file: str) -> None:
        if config_file == self._settings.nat_config_file:
            return
        try:
            Path(config_file).unlink(missing_ok=True)
        except OSError:
            pass


class AnalysisOrchestrator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._masker = _build_settings_masker(settings)
        self._nat = NemoWorkflowRunner(settings)
        self._collectors = [
            RunAICollector(settings),
            KubernetesCollector(settings),
            PostgresCollector(settings),
            PrometheusCollector(settings),
            LokiCollector(settings),
            SystemCollector(settings),
        ]
        # Optional change/timeline capability agent — probe-able tool once it exists.
        try:
            from app.collectors.change import ChangeCollector
        except ImportError:
            pass
        else:
            self._collectors.append(ChangeCollector(settings))

    async def analyze(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        """Run one analysis under an overall hard deadline.

        Per-step ceilings (collectors, LLM, NAT) are generous so agents gather deep
        evidence and think; this wrapper guarantees the whole run still finishes
        within `analysis_deadline_seconds` (default 5 min), returning a graceful
        degraded report if it overruns rather than hanging."""
        deadline = self._settings.analysis_deadline_seconds
        if not deadline or deadline <= 0:
            return await self._analyze_impl(request)
        try:
            return await asyncio.wait_for(self._analyze_impl(request), timeout=deadline)
        except TimeoutError:  # asyncio.TimeoutError is this builtin on 3.11+
            _log.warning("analysis exceeded the %ss deadline; returning degraded report", deadline)
            return self._deadline_response(request, deadline)

    def _deadline_response(
        self, request: AlertAnalysisRequest, deadline: int
    ) -> AlertAnalysisResponse:
        target = resolve_target(request.alert.labels, request.alert.annotations)
        ko = self._settings.language == "ko"
        summary = (
            f"분석이 {deadline}초 제한을 초과하여 중단되었습니다."
            if ko
            else f"Analysis was stopped after exceeding the {deadline}s deadline."
        )
        detail = (
            f"{summary} 증거 수집/추론이 예상보다 오래 걸렸습니다 — 재시도하거나 "
            "대상(네임스페이스/워크로드)을 좁혀 다시 실행해 주세요."
            if ko
            else f"{summary} Evidence gathering/reasoning took longer than expected — "
            "retry, or narrow the target (namespace/workload) and run again."
        )
        response = AlertAnalysisResponse(
            status="ok",
            thread_ts=request.thread_ts,
            analysis=detail,
            analysis_summary=summary,
            analysis_detail=detail,
            analysis_type=request.analysis_type or request.alert.status or "firing",
            analysis_quality="degraded",
            missing_data=[],
            warnings=[f"analysis exceeded the {deadline}s deadline and was stopped"],
            capabilities={},
            context={"target": target.__dict__, "deadline_seconds": deadline},
            artifacts=[],
        )
        return _mask_model(response, AlertAnalysisResponse, self._masker)

    async def _analyze_impl(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        target = resolve_target(request.alert.labels, request.alert.annotations)
        # Knowledge graph is consulted once here, at synthesis time, as a
        # knowledge resource for the final RCA — not as a parallel collector.
        kg_context = await enrich(self._settings, target)
        # Plan first (senior-SRE "think before you dig"): scope every collector to
        # what THIS alert needs instead of always scraping the control plane.
        plan = await plan_investigation(
            self._settings,
            target,
            request.alert,
            kg_context.as_dict(),
            list(request.similar_incidents),
        )
        nat_payload = request.model_dump(mode="json")
        nat_payload["mode"] = "alert_analysis"
        nat_payload["kg_context"] = kg_context.as_dict()
        nat_payload["plan"] = plan.as_dict()
        agent_souls = load_agent_souls(self._settings.agent_souls_file)
        nat_payload["agent_souls"] = agent_souls
        nat_text = None
        nat_warnings: list[str] = []
        try:
            nat_text = await self._nat.run(nat_payload)
        except Exception as exc:
            nat_warnings.append(_unexpected_runtime_warning("nemo", exc))

        # Synthesis MUST see EVERY collector's result. Await the full gather over ALL
        # collectors here, before any ranking/synthesis, and never synthesize from a
        # subset — an early/partial synthesis would produce a confident-but-wrong RCA.
        # LLM-gated senior-SRE loop when enabled; otherwise the one-shot gather. Both
        # return one CollectorResult per collector (investigate runs any it skipped).
        if llm_configured(self._settings) and self._settings.enable_investigation_loop:
            from app.services.investigator import investigate

            results = await investigate(
                self._settings,
                target,
                self._collectors,
                plan,
                kg_context.as_dict(),
                self._settings.max_investigation_steps,
            )
        else:
            results = list(
                await asyncio.gather(
                    *(_collect_safely(collector, target, plan) for collector in self._collectors)
                )
            )
        assert len(results) == len(self._collectors), (
            "synthesis must wait for all collectors: "
            f"{len(results)} results for {len(self._collectors)} collectors"
        )

        capabilities = {result.agent: result.status for result in results}
        artifacts = [artifact for result in results for artifact in result.artifacts]
        missing = sorted({item for result in results for item in result.missing_data})
        warnings = sorted(
            {item for result in results for item in result.warnings}
            | set(nat_warnings)
            | set(kg_context.warnings)
        )
        # Optional feedback-derived priors from operator hints — nudge ranking.
        priors = None
        try:
            from app.services.feedback_priors import derive_priors
        except ImportError:
            pass
        else:
            priors = derive_priors(request.feedback_hints)
        root_cause_candidates = rank_root_cause_candidates(
            target,
            results,
            occurrence_count=request.occurrence_count,
            kg_blast_radius=kg_context.blast_radius_workloads,
            priors=priors,
        )
        # Optional self-check: refute the top cause, apply its calibrated confidence
        # to the top candidate, and keep the caveat text for the report.
        self_check_caveat = ""
        self_check_refuted = False
        self_check_next = ""
        try:
            from app.services.self_check import refute_top_cause
        except ImportError:
            pass
        else:
            if root_cause_candidates:
                check = await refute_top_cause(
                    self._settings, root_cause_candidates[0], results
                )
                if isinstance(check, dict):
                    calibrated = check.get("confidence")
                    if calibrated in ("low", "medium", "high"):
                        root_cause_candidates[0].confidence = calibrated
                    self_check_caveat = str(check.get("caveat") or "").strip()
                    self_check_refuted = bool(check.get("refuted"))
                    self_check_next = str(check.get("next_check") or "").strip()
        # RE-ANALYSIS ON REFUTATION (LLM-gated): when the self-check refuted the top
        # cause, do EXACTLY ONE bounded re-analysis pass leading with the next-best
        # hypothesis. Hard guard: this block runs once and never re-enters analyze().
        reanalysis_note = ""
        if (
            self_check_refuted
            and root_cause_candidates
            and llm_configured(self._settings)
            and self._settings.enable_investigation_loop
        ):
            outcome = await self._reanalyze_once(
                target=target,
                plan=plan,
                kg_context=kg_context,
                results=results,
                request=request,
                priors=priors,
                refuted_family=root_cause_candidates[0].family,
                prior_candidates=root_cause_candidates,
            )
            if outcome is not None:
                (
                    results,
                    root_cause_candidates,
                    self_check_caveat,
                    reanalysis_note,
                    self_check_refuted,
                    self_check_next,
                ) = outcome
                # Re-derive the evidence aggregates from the merged results.
                capabilities = {result.agent: result.status for result in results}
                artifacts = [
                    artifact for result in results for artifact in result.artifacts
                ]
                missing = sorted(
                    {item for result in results for item in result.missing_data}
                )
                warnings = sorted(
                    {item for result in results for item in result.warnings}
                    | set(nat_warnings)
                    | set(kg_context.warnings)
                )
        # Graph-derived remediation from the validated TypeDB reasoning functions,
        # keyed to the ranked top family + any Xid codes / GPU model in the evidence.
        # Best-effort: an empty result when TypeDB is off/unreachable.
        top_family = (
            root_cause_candidates[0].family if root_cause_candidates else ""
        )
        graph_fixes = await graph_remediation(
            self._settings,
            family=top_family if top_family != "insufficient_evidence" else "",
            xid_codes=_xid_codes_from_results(results),
            gpu_model=_gpu_model_from(target, results),
        )
        warnings = sorted(set(warnings) | set(graph_fixes.warnings))
        # Optional change/timeline capability — added to the synthesis context.
        timeline = None
        try:
            from app.services.timeline import build_timeline
        except ImportError:
            pass
        else:
            timeline = build_timeline(results)
        quality = _quality_from(results)
        summary = _summary_from(request, results, root_cause_candidates)
        failure_modes = load_failure_modes(self._settings.failure_modes_file)
        known_issues = load_runai_known_issues(self._settings.runai_known_issues_file)
        # Version-aware precision: drop known issues already fixed in the cluster's
        # running Run:ai version so we don't attribute a symptom to a patched bug.
        known_issues = _suppress_fixed_known_issues(known_issues, _runai_version_from(results))
        # Adversarial precision: LLM-verify signature/keyword matches (known issues,
        # failure-mode symptoms, GPU XIDs) and drop ones the evidence doesn't support.
        # Best-effort + LLM-gated: with no LLM nothing is suppressed.
        observed = _observed_text(results)
        try:
            from app.services.self_check import verify_known_issues, verify_matches
        except ImportError:
            pass
        else:
            ki_matches = match_runai_known_issues(known_issues, observed)
            if ki_matches:
                refuted = await verify_known_issues(self._settings, ki_matches, results)
                if refuted:
                    known_issues = [k for k in known_issues if k.get("issue") not in refuted]

            ev_candidates = [
                {
                    "name": sym.get("symptom", ""),
                    "detail": f"{fam} — {'; '.join(sym.get('actions', [])[:1])}",
                }
                for fam, sym in match_failure_mode_symptoms(failure_modes, observed)
            ]
            ev_candidates += [
                {"name": f"XID {code}", "detail": "; ".join(graph_fixes.xid_fixes[code][:1])}
                for code in graph_fixes.xid_fixes
            ]
            if ev_candidates:
                refuted = await verify_matches(
                    self._settings, ev_candidates, results, subject="matched symptom or GPU XID"
                )
                if refuted:
                    failure_modes = {
                        fam: [s for s in syms if s.get("symptom") not in refuted]
                        for fam, syms in failure_modes.items()
                    }
                    for label in refuted:
                        if label.startswith("XID "):
                            try:
                                code = int(label[4:])
                            except ValueError:
                                continue
                            graph_fixes.xid_fixes.pop(code, None)
                            graph_fixes.root_xids.pop(code, None)
        playbook_fallback = load_troubleshooting_cases(
            self._settings.troubleshooting_cases_file
        )
        detail = nat_text if nat_text else _detail_from(
            request,
            results,
            missing,
            failure_modes,
            playbook_fallback,
            agent_souls,
            root_cause_candidates,
            kg_context.as_dict(),
            plan,
            graph_fixes,
            language=getattr(self._settings, "language", "en"),
            known_issues=known_issues,
        )
        # Korean LLM synthesis (preferred when language == "ko" and LLM configured):
        # rewrite summary + detail grounded STRICTLY in the evidence just gathered.
        # Falls back to the deterministic English report on any failure.
        if not nat_text and getattr(self._settings, "language", "en") == "ko" \
                and llm_configured(self._settings):
            synth = await _synthesize_korean(
                self._settings,
                request=request,
                results=results,
                plan=plan,
                root_cause_candidates=root_cause_candidates,
                kg_context=kg_context.as_dict(),
                graph_fixes=graph_fixes,
                fallback_detail=detail,
            )
            if synth:
                summary, detail = synth

        # Self-check caveat (optional hook) + re-analysis note — inserted BEFORE the
        # appendix so the document reads problem -> cause -> actions -> checks -> appendix.
        self_check_lines = [text for text in (self_check_caveat, reanalysis_note) if text]
        if self_check_lines:
            detail = _insert_before_appendix(
                detail, "## Self-Check\n\n" + "\n\n".join(self_check_lines)
            )

        # Operator questions: when the RCA could not settle (insufficient evidence,
        # or still refuted after re-analysis), honestly ask for the missing inputs.
        if top_family in ("", "insufficient_evidence") or self_check_refuted:
            try:
                questions = await _operator_questions(
                    self._settings, missing, plan, target, self_check_next
                )
            except Exception:  # noqa: BLE001 - questions are best-effort
                questions = []
            if questions:
                header = (
                    "## 추가 확인 요청"
                    if getattr(self._settings, "language", "en") == "ko"
                    else "## Questions for the Operator"
                )
                body = "\n".join(f"- {question}" for question in questions)
                detail = _insert_before_appendix(detail, f"{header}\n\n{body}")

        response = AlertAnalysisResponse(
            status="ok",
            thread_ts=request.thread_ts,
            analysis=detail,
            analysis_summary=summary,
            analysis_detail=detail,
            analysis_type=request.analysis_type or request.alert.status or "firing",
            analysis_quality=quality,
            missing_data=missing,
            warnings=warnings,
            capabilities=capabilities,
            context={
                "target": target.__dict__,
                "nemo_runtime": "enabled" if self._nat.enabled() else "fallback",
                "occurrence_count": request.occurrence_count,
                "occurrence_pods": request.occurrence_pods,
                "similar_incidents": [
                    item.model_dump(mode="json") for item in request.similar_incidents
                ],
                "feedback_hints": [
                    item.model_dump(mode="json") for item in request.feedback_hints
                ],
                "agent_souls_file": self._settings.agent_souls_file,
                "agent_souls_applied": bool(agent_souls),
                "root_cause_candidates": [
                    candidate.as_dict() for candidate in root_cause_candidates
                ],
                "top_root_cause": (
                    root_cause_candidates[0].as_dict() if root_cause_candidates else None
                ),
                "knowledge_base": kg_context.as_dict(),
                "plan": plan.as_dict(),
                **({"timeline": timeline} if timeline else {}),
            },
            artifacts=artifacts,
        )
        return _mask_model(response, AlertAnalysisResponse, self._masker)

    async def summarize_incident(
        self, request: IncidentSummaryRequest
    ) -> IncidentSummaryResponse:
        alerts = request.alerts
        title = request.title if request.title and request.title != "Ongoing" else "Run:AI incident"
        summaries = [
            alert.analysis_summary
            for alert in alerts
            if alert.analysis_summary and alert.analysis_summary.strip()
        ]
        summary = summaries[0] if summaries else f"{len(alerts)} alert(s) were correlated."
        detail_lines = [
            "## Incident Summary",
            "",
            f"- Incident: {request.incident_id}",
            f"- Severity: {request.severity}",
            f"- Alert count: {len(alerts)}",
            f"- Window: {request.fired_at} to {request.resolved_at}",
            "",
            "## Alert Evidence",
        ]
        for alert in alerts:
            detail_lines.append(
                f"- {alert.alert_name} ({alert.status}, {alert.severity}): "
                f"{alert.analysis_summary or 'No analysis summary yet.'}"
            )
        response = IncidentSummaryResponse(
            status="ok",
            title=title,
            summary=summary,
            detail="\n".join(detail_lines),
        )
        return _mask_model(response, IncidentSummaryResponse, self._masker)

    async def chat(self, request: ChatRequest) -> ChatResponse:
        context = dict(request.context or {})
        llm_configured = bool(
            self._settings.llm_base_url and self._settings.llm_model and self._settings.llm_api_key
        )
        context["agent_service"] = {
            "nemo_runtime": "enabled" if self._nat.enabled() else "fallback",
            "chat_mode": "llm" if llm_configured else "deterministic_context",
            "chat_llm_runtime": "active" if llm_configured else "not_directly_used",
            "llm_configured": llm_configured,
            "nat_config_file": self._settings.nat_config_file,
            "runai_configured": bool(self._settings.runai_base_url),
            "prometheus_configured": bool(self._settings.prometheus_url),
            "loki_configured": bool(self._settings.loki_url),
            "postgres_configured": bool(self._settings.postgres_dsn),
        }
        entity = (
            request.incident_id
            or request.alert_id
            or context.get("incident_id")
            or context.get("alert_id")
            or request.page
            or "current RCA workspace"
        )
        grounding = _chat_answer_from_context(request, context, str(entity), self._masker)
        answer = grounding
        if llm_configured:
            try:
                llm_answer = await self._llm_chat_answer(request, grounding)
            except Exception as exc:
                warning = self._masker.mask_text(_unexpected_runtime_warning("llm", exc))
                answer = _append_chat_warning(grounding, warning)
            else:
                if llm_answer:
                    answer = self._masker.mask_text(llm_answer)
        response = ChatResponse(
            status="ok",
            answer=answer,
            message=answer,
            response=answer,
            conversation_id=request.conversation_id or f"chat-{uuid4().hex[:10]}",
        )
        return _mask_model(response, ChatResponse, self._masker)

    async def _reanalyze_once(
        self,
        *,
        target: AnalysisTarget,
        plan: InvestigationPlan,
        kg_context: object,
        results: list[CollectorResult],
        request: AlertAnalysisRequest,
        priors: dict[str, float] | None,
        refuted_family: str,
        prior_candidates: list[RankedCause],
    ) -> tuple[list[CollectorResult], list[RankedCause], str, str, bool, str] | None:
        """EXACTLY ONE bounded re-analysis pass after the self-check refuted the top cause.

        Leads with the next-best hypothesis, re-runs a small investigation, merges the
        fresh evidence by agent name, re-ranks, and refutes the new top ONCE. Returns
        (results, candidates, caveat, note, refuted, next_check), or None on ANY
        failure so the caller keeps the pre-re-analysis result. Never re-enters.
        """
        try:
            from app.services.investigator import investigate
            from app.services.self_check import refute_top_cause

            kg_dict = kg_context.as_dict()  # type: ignore[attr-defined]
            kg_blast = getattr(kg_context, "blast_radius_workloads", 0)
            # Next-best hypothesis: candidates[1] when usable, else re-rank and take
            # the best family that is neither the refuted one nor the fallback gate.
            next_cause = None
            pool = list(prior_candidates[1:]) or rank_root_cause_candidates(
                target,
                results,
                occurrence_count=request.occurrence_count,
                top_n=5,
                kg_blast_radius=kg_blast,
                priors=priors,
            )
            for candidate in pool:
                if candidate.family not in (refuted_family, "insufficient_evidence"):
                    next_cause = candidate
                    break
            if next_cause is None:
                return None

            lead = {
                "family": next_cause.family,
                "reason": "re-analysis after the first conclusion was refuted",
            }
            rest = [
                h
                for h in (plan.hypotheses or [])
                if isinstance(h, dict) and h.get("family") != next_cause.family
            ]
            replan = replace(plan, hypotheses=[lead, *rest])
            fresh = await investigate(
                self._settings,
                target,
                self._collectors,
                replan,
                kg_dict,
                min(self._settings.max_reanalysis_steps, self._settings.max_investigation_steps),
            )
            merged = {result.agent: result for result in results}
            for result in fresh:
                merged[result.agent] = result
            merged_results = list(merged.values())

            candidates = rank_root_cause_candidates(
                target,
                merged_results,
                occurrence_count=request.occurrence_count,
                kg_blast_radius=kg_blast,
                priors=priors,
            )
            caveat = ""
            refuted = False
            next_check = ""
            if candidates:
                check = await refute_top_cause(
                    self._settings, candidates[0], merged_results
                )
                if isinstance(check, dict):
                    calibrated = check.get("confidence")
                    if calibrated in ("low", "medium", "high"):
                        candidates[0].confidence = calibrated
                    caveat = str(check.get("caveat") or "").strip()
                    refuted = bool(check.get("refuted"))
                    next_check = str(check.get("next_check") or "").strip()
            new_family = candidates[0].family if candidates else "insufficient_evidence"
            if getattr(self._settings, "language", "en") == "ko":
                note = (
                    f"1차 결론({refuted_family})이 반증되어 재분석을 수행했습니다 → "
                    f"재분석 결론: {new_family}"
                )
            else:
                note = (
                    f"The initial conclusion ({refuted_family}) was refuted, so one "
                    f"re-analysis pass was performed → revised conclusion: {new_family}."
                )
            return merged_results, candidates, caveat, note, refuted, next_check
        except Exception:  # noqa: BLE001 - re-analysis is best-effort; keep 1st result
            return None

    async def _llm_chat_answer(self, request: ChatRequest, grounding: str) -> str | None:
        question = (request.message or "").strip()
        if not question:
            return None
        system = (
            "You are the RCA copilot for an NVIDIA Run:AI GPU platform. Answer the operator's "
            "question conversationally and concisely using only the grounded context provided. "
            "If the context lacks the answer, say so and suggest the next diagnostic step. "
            "Reply in the operator's language."
        )
        payload = {
            "model": self._settings.llm_model,
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": f"Grounded context:\n{grounding}\n\nQuestion: {question}",
                },
            ],
            "temperature": 0.2,
        }
        response = await post_json(
            url=f"{self._settings.llm_base_url}/chat/completions",
            timeout_seconds=self._settings.llm_request_timeout_seconds,
            json_body=payload,
            headers={"Authorization": f"Bearer {self._settings.llm_api_key}"},
        )
        if not response.ok or not isinstance(response.data, dict):
            return None
        choices = response.data.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message") if isinstance(choices[0], dict) else None
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip()
        return None


async def _synthesize_korean(
    settings: Settings,
    *,
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    plan: InvestigationPlan,
    root_cause_candidates: list[RankedCause],
    kg_context: dict,
    graph_fixes: GraphRemediation,
    fallback_detail: str,
) -> tuple[str, str] | None:
    """LLM synthesis of the RCA report in Korean, grounded STRICTLY in the evidence.

    Returns (analysis_summary, analysis_detail) in Korean, or None on any failure so
    the caller keeps the deterministic English report. Never raises into analyze().
    """
    from app.collectors.http_json import compact

    evidence = {
        "alert": {
            "name": request.alert.labels.get("alertname"),
            "labels": request.alert.labels,
            "annotations": request.alert.annotations,
        },
        "plan": plan.as_dict(),
        "ranked_root_cause_candidates": [c.as_dict() for c in root_cause_candidates],
        "collector_findings": [
            {
                "agent": r.agent,
                "status": r.status,
                "confidence": r.confidence,
                "summary": r.summary,
            }
            for r in results
        ],
        "knowledge_graph": {
            "blast_radius_workloads": kg_context.get("blast_radius_workloads"),
            "prior_incidents": kg_context.get("prior_incidents"),
            "knowledge": kg_context.get("knowledge"),
        },
        "graph_remediation": graph_fixes.as_dict(),
        "matched_alert": plan.matched_alert,
        "similar_incidents": [
            {
                "incident_id": i.incident_id,
                "similarity": i.similarity,
                "analysis_summary": i.analysis_summary or i.title,
            }
            for i in request.similar_incidents
            if (i.similarity or 0) >= _SIMILARITY_FLOOR
        ],
    }
    system = (
        "당신은 NVIDIA Run:ai GPU 플랫폼을 담당하는 시니어 SRE입니다. 제공된 증거(수집기별 "
        "발견 사항, 조사 계획, 순위가 매겨진 원인 후보, 지식 그래프/함수 기반 조치, 매칭된 "
        "내장 알림, 유사 인시던트)에만 근거하여 한국어로 장애 분석 보고서를 작성하세요.\n"
        "규칙:\n"
        "- 반드시 한국어로, 비전문가도 이해할 수 있게 작성합니다 (전문용어는 풀어서).\n"
        "- 길게 쓰지 마세요. 아래 1~3 섹션 합쳐서 A4 한 페이지 이내가 목표입니다.\n"
        "- 증거에 없는 사실을 절대 만들어내지 마세요.\n"
        "- 특정 수집기가 아무것도 찾지 못했으면 '증거를 찾기 어렵습니다.'라고 명시하세요.\n"
        "- 반드시 이 문서 구조를 따르세요 (Word 제출용이므로 헤딩/번호목록만 사용, 표·HTML 금지):\n"
        "  # 장애 분석 보고서 — {알림명}\n"
        "  발생/심각도/대상 메타 한 줄\n"
        "  ## 1. 문제 (Problem) — 무엇이/어디서/언제부터/어떤 영향, 3~4문장.\n"
        "  ## 2. 원인 (Root Cause) — 결론 한 문장 먼저, 그다음 뒷받침 근거 2~4개(수집기별 "
        "핵심 발견: 관찰한 것과 시작 시점), XID 인과 사슬이 있으면 명시 "
        "(예: 'XID 74(NVLink) → XID 45 앱 크래시 — 뿌리는 NVLink').\n"
        "  ## 3. 권장 조치 (Recommended Actions) — 번호 목록, 즉시/후속/예방 순서, "
        "구체적 명령·확인 포함, 중복 금지.\n"
        "  ## 4. 부록 (Appendix) — 수집기별 증거 한 줄씩, 조사 계획 요약.\n"
        '- 반드시 JSON 객체 하나로만 응답하세요: {"summary": <한국어 한 문장: 문제+원인 요약>, '
        '"detail": <위 구조의 한국어 마크다운 본문>}'
    )
    user = "증거(JSON):\n" + json.dumps(
        compact(evidence, limit=8), ensure_ascii=False, default=str
    )
    try:
        data = await _complete_synthesis_json(settings, system=system, user=user)
    except Exception:  # noqa: BLE001 - synthesis is best-effort; keep deterministic report
        return None
    if not data:
        return None
    summary = data.get("summary")
    detail = data.get("detail")
    if not isinstance(summary, str) or not summary.strip():
        return None
    if not isinstance(detail, str) or not detail.strip():
        detail = fallback_detail
    return _short_sentence(summary, limit=280), detail.strip()


async def _complete_synthesis_json(
    settings: Settings, *, system: str, user: str
) -> dict | None:
    text = await complete(
        settings,
        system=system + "\n\nJSON 객체 하나로만, 프롬프트나 코드펜스 없이 응답하세요.",
        user=user,
        temperature=0.2,
    )
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1] if "\n" in cleaned else cleaned
        cleaned = cleaned.removeprefix("json").strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[: cleaned.rfind("```")].strip()
    try:
        parsed = json.loads(cleaned)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _quality_from(results: list[CollectorResult]) -> str:
    counts = Counter(result.status for result in results)
    if counts["ok"] >= 3:
        return "high"
    if counts["ok"] >= 1 or counts["partial"] >= 2:
        return "medium"
    return "low"


async def _collect_safely(
    collector: object, target: object, plan: object = None
) -> CollectorResult:
    try:
        return await collector.collect(target, plan)  # type: ignore[attr-defined]
    except Exception as exc:
        agent = _collector_name(collector)
        return CollectorResult(
            agent=agent,
            status="unavailable",
            summary=f"{agent} collector failed unexpectedly before returning evidence.",
            confidence="low",
            details={"error": f"{type(exc).__name__}: {exc}"},
            missing_data=[f"{agent}.collector_exception"],
            warnings=[_unexpected_runtime_warning(agent, exc)],
        )


def _collector_name(collector: object) -> str:
    name = collector.__class__.__name__
    if name.endswith("Collector"):
        name = name[: -len("Collector")]
    normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return normalized.replace("_a_i", "ai") or "collector"


def _unexpected_runtime_warning(component: str, exc: Exception) -> str:
    return f"{component} failed unexpectedly: {type(exc).__name__}: {exc}"


def _append_chat_warning(answer: str, warning: str) -> str:
    if "## Warnings" in answer:
        return f"{answer}\n- {warning}"
    return "\n".join([answer, "", "## Warnings", "", f"- {warning}"])


def _build_settings_masker(settings: Settings) -> Masker:
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


def _mask_model(model: TModel, model_type: type[TModel], masker: Masker) -> TModel:
    payload = model.model_dump(mode="json")
    return model_type.model_validate(masker.mask_object(payload))


def _extract_nat_result(output: str) -> str | None:
    if not output:
        return None
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", output)
    marker = "Workflow Result:"
    if marker not in cleaned:
        return cleaned.strip() or None
    result = cleaned.split(marker, 1)[1]
    result = result.split("--------------------------------------------------", 1)[0]
    return result.strip() or None


def _summary_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    root_cause_candidates: list[RankedCause],
) -> str:
    return _short_sentence(
        _ranked_root_cause_statement(root_cause_candidates, request), limit=280
    )


# Section headings for the report document (Word-export-clean markdown).
_HEADINGS = {
    "en": {
        "title": "# Incident Analysis Report",
        "problem": "## 1. Problem",
        "cause": "## 2. Root Cause",
        "actions": "## 3. Recommended Actions",
        "appendix": "## 4. Appendix",
        "fired": "Fired",
        "severity": "Severity",
        "target": "Target",
        "what": "What",
        "where": "Where",
        "impact": "Impact",
    },
    "ko": {
        "title": "# 장애 분석 보고서",
        "problem": "## 1. 문제 (Problem)",
        "cause": "## 2. 원인 (Root Cause)",
        "actions": "## 3. 권장 조치 (Recommended Actions)",
        "appendix": "## 4. 부록 (Appendix)",
        "fired": "발생",
        "severity": "심각도",
        "target": "대상",
        "what": "증상",
        "where": "위치",
        "impact": "영향",
    },
}


def _detail_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    missing: list[str],
    failure_modes: dict[str, list[dict]] | None = None,
    troubleshooting_cases: str = "",
    agent_souls: str = "",
    root_cause_candidates: list[RankedCause] | None = None,
    kg_context: dict | None = None,
    plan: InvestigationPlan | None = None,
    graph_fixes: GraphRemediation | None = None,
    language: str = "en",
    known_issues: list[dict] | None = None,
) -> str:
    """Problem -> Root Cause -> Recommended Actions, then everything else in an
    appendix. Sections 1-3 are the ~1-page report an operator (or a Word export)
    actually reads; the appendix keeps the full evidence trail."""
    h = _HEADINGS.get(language, _HEADINGS["en"])
    labels = request.alert.labels
    annotations = request.alert.annotations
    alert_name = labels.get("alertname") or request.alert.labels.get("alert_name") or "alert"
    target = resolve_target(labels, annotations)

    # --- header -------------------------------------------------------------
    meta = [f"{h['severity']}: {target.severity}"]
    if request.alert.startsAt:
        meta.insert(0, f"{h['fired']}: {request.alert.startsAt}")
    where = " / ".join(
        part for part in (target.namespace, target.workload_name or target.pod, target.node)
        if part
    )
    if where:
        meta.append(f"{h['target']}: {where}")
    lines = [f"{h['title']} — {alert_name}", "", " · ".join(meta), ""]

    # --- 1. Problem -----------------------------------------------------------
    lines.extend([h["problem"], ""])
    lines.append(f"- {h['what']}: {_root_cause_statement(request)}")
    if where:
        lines.append(f"- {h['where']}: {where}")
    if request.occurrence_count > 1:
        impact = (
            f"같은 워크로드에서 {request.occurrence_count}회 반복 발생"
            if language == "ko"
            else f"recurred {request.occurrence_count} times on the same workload"
        )
        lines.append(f"- {h['impact']}: {impact}")

    # --- 2. Root Cause --------------------------------------------------------
    lines.extend(["", h["cause"], ""])
    lines.append(_ranked_root_cause_statement(root_cause_candidates or [], request))
    # Ground the coarse family in the most specific signature match when one exists:
    # a recognised known issue (with its affected/fixed version) is far more precise.
    lines.extend(_known_issue_cause_lines(known_issues, _observed_text(results), language))
    supporting = _supporting_evidence(results)
    if supporting:
        lines.append("")
        lines.extend(f"- **{agent}**: {finding}" for agent, finding in supporting)
    causal = _causal_chain_line(graph_fixes, language)
    if causal:
        lines.extend(["", causal])

    # --- 3. Recommended Actions ------------------------------------------------
    lines.extend(["", h["actions"], ""])
    numbered = _numbered_actions(
        plan,
        graph_fixes,
        root_cause_candidates,
        _observed_text(results),
        failure_modes or {},
        missing,
        request,
        known_issues or [],
    )
    if numbered:
        lines.extend(numbered)
    else:
        # Never a dangling empty section — say honestly why there are no actions.
        lines.append(
            "증거가 부족하여 구체적인 조치를 제시하기 어렵습니다. "
            "아래 확인 요청을 먼저 진행해 주세요."
            if language == "ko"
            else "Not enough evidence for concrete actions yet — please address the "
            "questions below first."
        )

    # --- 4. Appendix (full evidence trail; children demoted to ###) -----------
    lines.extend(["", h["appendix"], "", "### Evidence", ""])
    for result in results:
        lines.append(f"- **{result.agent}**: {_best_evidence_line(result)}")
    lines.extend(_investigation_plan_lines(plan))
    lines.extend(
        _knowledge_base_lines(kg_context, root_cause_candidates, _observed_text(results))
    )
    operator_prompt = annotations.get("operator_prompt")
    if operator_prompt:
        lines.extend(["", "### Operator Guidance", "", operator_prompt])
    lines.extend(["", "### Agent Role Coverage", ""])
    lines.extend(agent_role_coverage_lines())
    if not agent_souls:
        lines.append("- Agent role contract file was not loaded; fallback guidance was used.")
    lines.extend(_affected_pods_lines(request))
    lines.extend(["", "### Troubleshooting Playbook", ""])
    lines.extend(
        _playbook_lines(
            root_cause_candidates,
            _observed_text(results),
            failure_modes or {},
            troubleshooting_cases,
        )
    )
    lines.extend(_similar_incident_lines(request))
    lines.extend(_feedback_hint_lines(request))
    lines.extend(
        [
            "",
            "### Alert Labels",
            "",
            "```json",
            json.dumps(labels, indent=2, sort_keys=True),
            "```",
        ]
    )
    return "\n".join(lines)


def _insert_before_appendix(detail: str, block: str) -> str:
    """Insert a section before the appendix so it reads as part of the report body.

    Falls back to appending at the end when no appendix heading exists (e.g. an
    LLM-synthesized or NAT-produced detail with a different shape).
    """
    for heading in ("\n## 4. 부록", "\n## 4. Appendix"):
        idx = detail.find(heading)
        if idx >= 0:
            return f"{detail[:idx]}\n{block}\n{detail[idx:]}"
    return f"{detail}\n\n{block}"


def _supporting_evidence(results: list[CollectorResult]) -> list[tuple[str, str]]:
    """Up to 4 (agent, finding) pairs with a REAL finding — no no-evidence lines."""
    picked: list[tuple[str, str]] = []
    for result in results:
        if result.status not in ("ok", "partial"):
            continue
        if (result.summary or "").startswith(NO_EVIDENCE):
            continue
        line = _best_evidence_line(result)
        if line.startswith(NO_EVIDENCE):
            continue
        picked.append((result.agent, line))
        if len(picked) >= 4:
            break
    return picked


def _causal_chain_line(graph_fixes: GraphRemediation | None, language: str) -> str:
    """One line naming the XID causal picture when the graph produced one.

    When the ontology's leads_to chain resolves a ROOT fault for an observed XID
    (e.g. NVLink Xid 74 -> app-crash Xid 45), name the chain so the operator fixes
    the origin, not the downstream symptom — the drill-down precision win."""
    if graph_fixes is None or not graph_fixes.xid_fixes:
        return ""
    codes = ", ".join(str(code) for code in sorted(graph_fixes.xid_fixes))
    roots = getattr(graph_fixes, "root_xids", None) or {}
    chain = "; ".join(
        dict.fromkeys(
            f"XID {root} → XID {observed}"
            for observed, root_list in sorted(roots.items())
            for root in root_list
        )
    )
    if language == "ko":
        if chain:
            return (
                f"- 관련 GPU 오류(XID): {codes} — 인과 사슬(뿌리→관측): {chain}. "
                "뿌리 XID를 먼저 조치하세요."
            )
        return f"- 관련 GPU 오류(XID): {codes} — 세부 조치는 아래 권장 조치를 참고."
    if chain:
        return (
            f"- Related GPU errors (XID): {codes} — causal chain (root → observed): "
            f"{chain}. Fix the root XID first."
        )
    return f"- Related GPU errors (XID): {codes} — see the recommended actions below."


def _runai_version_from(results: list[CollectorResult]) -> str:
    """The running Run:ai control-plane version, if the runai collector resolved one."""
    for result in results:
        if result.agent == "runai":
            value = result.details.get("runai_version")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", text or "")[:4])


def _known_issue_fixed_in_running(issue: dict, running_version: str) -> bool:
    """True when the cluster's Run:ai version is at/after the issue's fixed version:
    the bug is already patched here, so surfacing it would be a false positive."""
    fixed = _version_tuple(str(issue.get("fixed_version") or ""))
    running = _version_tuple(running_version)
    return bool(fixed and running and running >= fixed)


def _suppress_fixed_known_issues(known_issues: list[dict], running_version: str) -> list[dict]:
    """Drop known issues already fixed in the running Run:ai version (precision:
    don't attribute a symptom to a bug the cluster is already patched against)."""
    if not running_version:
        return known_issues
    return [k for k in known_issues if not _known_issue_fixed_in_running(k, running_version)]


def _known_issue_cause_lines(
    known_issues: list[dict] | None, observed_text: str, language: str
) -> list[str]:
    """Ground the root cause in a recognised known issue — more precise than the
    coarse family. Names the issue and its affected/fixed Run:ai version. Returns
    the grounded line(s), or [] when no known-issue signature matches the evidence."""
    matches = match_runai_known_issues(known_issues or [], observed_text)
    out: list[str] = []
    for issue in matches[:2]:  # the strongest signature hits only
        name = str(issue.get("issue") or "").strip()
        reason = " ".join(str(issue.get("reason") or "").split())
        affected = str(issue.get("affected_version") or "").strip()
        fixed = str(issue.get("fixed_version") or "").strip()
        ver = ""
        if affected or fixed:
            head = affected or "?"
            if language == "ko":
                ver = f" (영향 버전: {head}" + (f", 수정: {fixed}" if fixed else "") + ")"
            else:
                ver = f" (affected {head}" + (f", fixed in {fixed}" if fixed else "") + ")"
        label = "알려진 이슈로 인식" if language == "ko" else "Recognised known issue"
        line = f"- {label}: **{name}**{ver}"
        if reason:
            line += f" — {reason}"
        out.append(line)
    return out


def _numbered_actions(
    plan: InvestigationPlan | None,
    graph_fixes: GraphRemediation | None,
    candidates: list[RankedCause] | None,
    observed_text: str,
    failure_modes: dict[str, list[dict]],
    missing: list[str],
    request: AlertAnalysisRequest,
    known_issues: list[dict] | None = None,
) -> list[str]:
    """One deduped, numbered priority list — documented-alert fixes first, then
    recognised known-issue fixes, then graph-derived and curated family fixes,
    then infra-restore steps."""
    ordered: list[str] = []
    if plan is not None and plan.matched_alert:
        ordered.extend(str(a) for a in plan.matched_alert.get("actions", []))
    # Known operator cases recognised by their signature keywords in the evidence
    # (ranking-independent): version-regression / observability / expected-behavior
    # fixes surface even when the coarse family ranking points elsewhere.
    for issue in match_runai_known_issues(known_issues or [], observed_text):
        ordered.extend(str(a) for a in issue.get("actions", []))
    if graph_fixes is not None:
        ordered.extend(graph_fixes.family_fixes)
        root_codes = {r for roots in graph_fixes.root_xids.values() for r in roots}
        # Fix the ROOT of the causal chain before its downstream symptoms.
        for code in sorted(graph_fixes.xid_fixes, key=lambda c: (c not in root_codes, c)):
            label = "root XID" if code in root_codes else "XID"
            ordered.extend(f"({label} {code}) {fix}" for fix in graph_fixes.xid_fixes[code])
    # Curated failure-mode fixes: entry point is the fine-grained signature match
    # across ALL families (ranker orders, doesn't gate) — so a precise fix surfaces
    # even from a family the ranker mis-scored or can't nominate (gpu_hardware_error).
    top_family = candidates[0].family if candidates else ""
    for _family, symptom in match_failure_mode_symptoms(failure_modes, observed_text, top_family):
        ordered.extend(str(a) for a in symptom.get("actions", []))
    ordered.extend(
        line.removeprefix("- ") for line in _recommended_action_lines(missing, request)
    )
    seen: set[str] = set()
    numbered: list[str] = []
    for action in ordered:
        action = " ".join(action.split())
        if not action or action in seen:
            continue
        seen.add(action)
        numbered.append(f"{len(numbered) + 1}. {action}")
        if len(numbered) >= 8:
            break
    return numbered


def _root_cause_statement(request: AlertAnalysisRequest) -> str:
    annotations = request.alert.annotations
    labels = request.alert.labels
    text = (
        annotations.get("description")
        or annotations.get("summary")
        or labels.get("alertname")
        or "The alert fired before the agent could identify a precise root cause."
    )
    return _short_sentence(text, limit=320)


def _ranked_root_cause_statement(
    candidates: list[RankedCause], request: AlertAnalysisRequest
) -> str:
    subject = _as_sentence(_root_cause_statement(request))
    if not candidates:
        return subject
    top = candidates[0]
    if top.family == "insufficient_evidence":
        return _short_sentence(
            f"{subject} There is not yet enough evidence to point at a specific cause; "
            "the collected signals are inconclusive.",
            limit=320,
        )
    explanation = _FAMILY_EXPLANATION.get(top.family) or _family_label(top.family)
    return _short_sentence(f"{subject} Likely cause: {explanation}.", limit=320)


def _as_sentence(text: str) -> str:
    text = " ".join((text or "").split())
    if text and text[-1] not in ".!?":
        text += "."
    return text


# Plain-language cause per family for operator-facing summaries — no scores,
# confidence words, or keyword-match jargon.
_FAMILY_EXPLANATION = {
    "node_kubelet_pressure": (
        "the node hosting this workload is under resource pressure (disk, memory, or "
        "PID), which can evict or restart its pods"
    ),
    "scheduling_quota_exhaustion": (
        "the workload cannot be scheduled — GPU quota or queue capacity looks exhausted"
    ),
    "control_plane_error": (
        "the Run:ai control plane (scheduler or backend) is reporting errors that "
        "affect this workload"
    ),
    "workload_startup_image_failure": (
        "the workload itself is failing to start — an image pull, crash loop, or a "
        "startup/configuration error"
    ),
}


def _observed_text(results: list[CollectorResult]) -> str:
    parts: list[str] = []
    for result in results:
        if result.summary:
            parts.append(result.summary)
        parts.extend(art.summary for art in result.artifacts if art.summary)
    return " ".join(parts).lower()


def _knowledge_base_lines(
    kg_context: dict | None,
    candidates: list[RankedCause] | None = None,
    observed_text: str = "",
) -> list[str]:
    if not kg_context or not kg_context.get("enabled"):
        return []
    if not kg_context.get("available"):
        # Optional enrichment; when it is not available we simply omit the section
        # rather than surfacing infra jargon. The reason is carried in `warnings`.
        return []
    body: list[str] = []
    blast = kg_context.get("blast_radius_workloads") or 0
    if blast:
        body.append(
            f"- Blast radius: {blast} workload(s) share the alerting node, so the impact "
            "is node-wide rather than a single workload."
        )
    prior = kg_context.get("prior_incidents") or []
    if prior:
        body.append(f"- This alert recurred in {len(prior)} prior incident(s):")
        for item in prior[:5]:
            summary = item.get("analysis_summary") or "(no stored RCA summary)"
            body.append(f"  - {item.get('incident_id')}: {summary}")
    body.extend(_kb_remediation_lines(kg_context, candidates, observed_text))
    if not body:
        body.append("- No related knowledge-graph facts were found for this entity yet.")
    return ["", "### Knowledge Base (Ontology)", "", *body]


def _kb_remediation_lines(
    kg_context: dict, candidates: list[RankedCause] | None, observed_text: str
) -> list[str]:
    knowledge = kg_context.get("knowledge") or {}
    if not knowledge:
        return []
    # Entry point = the fine-grained signature match across ALL families, not the
    # coarse ranked family (which can be wrong, or can't even nominate the right one
    # such as gpu_hardware_error). The ranker only orders the matches.
    top_family = candidates[0].family if candidates else ""
    for family, symptom in match_failure_mode_symptoms(knowledge, observed_text, top_family):
        actions = symptom.get("actions", [])
        if actions:
            header = (
                f"- Matched symptom **{symptom.get('symptom')}** "
                f"({_family_label(family)}); known fixes from the knowledge base:"
            )
            return [header, *[f"  - {a}" for a in actions[:5]]]
    # No symptom keyword matched the observed evidence: don't dump a generic family
    # checklist as if it were a match — say so plainly.
    return ["- No closely-matching prior knowledge for this evidence yet."]


def _playbook_lines(
    candidates: list[RankedCause] | None,
    observed_text: str,
    failure_modes: dict[str, list[dict]],
    fallback_cases: str,
) -> list[str]:
    """Root-cause-relevant remediation.

    Precise first: every curated symptom whose keyword matches the evidence, across
    ALL families (the fine-grained signature is the entry point, not the coarse
    ranked family). Only when nothing matches does it fall back to the ranked
    family's general checklist, then the full case library.
    """
    top_family = candidates[0].family if candidates else ""
    matches = match_failure_mode_symptoms(failure_modes, observed_text, top_family)
    if matches:
        lines: list[str] = []
        for family, symptom in matches:
            lines.append(f"- **{symptom.get('symptom')}** ({_family_label(family)})")
            lines.extend(f"  - {action}" for action in symptom.get("actions", [])[:5])
        return lines
    # No precise signature matched: fall back to the ranked family's general
    # checklist (the coarse ranking's legitimate role), else the full case library.
    symptoms = failure_modes.get(top_family) if top_family else None
    if symptoms:
        actions = sorted({a for s in symptoms for a in s.get("actions", [])})
        header = f"Guidance for the most likely cause: **{_family_label(top_family)}**."
        return [header, "", *[f"- {action}" for action in actions[:6]]]
    if fallback_cases:
        return [fallback_cases]
    return ["- No troubleshooting guidance is available for this cause yet."]


def _family_label(family: str) -> str:
    labels = {
        "node_kubelet_pressure": "node kubelet pressure",
        "scheduling_quota_exhaustion": "scheduling quota exhaustion",
        "control_plane_error": "Run:ai control-plane error",
        "workload_startup_image_failure": "workload startup/image failure",
        "gpu_hardware_error": "GPU hardware error",
        "platform_version_bug": "Run:ai version bug",
        "observability_accuracy": "metrics/observability accuracy",
        "expected_known_behavior": "expected/known behavior",
        "insufficient_evidence": "insufficient evidence",
    }
    return labels.get(family, family.replace("_", " "))


def _short_sentence(value: str, *, limit: int) -> str:
    text = " ".join(value.split())
    if not text:
        return "The agent has not received enough alert context to name a root cause."
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _investigation_plan_lines(plan: InvestigationPlan | None) -> list[str]:
    if plan is None:
        return []
    matched = []
    if plan.used_similarity:
        matched.append("a similar past incident")
    if plan.used_ontology:
        matched.append("knowledge-graph facts")
    matched_text = (
        "matched " + " and ".join(matched)
        if matched
        else "nothing prior matched — reasoning from live evidence"
    )
    lines = [
        "",
        "### Investigation Plan",
        "",
        f"- Focus: {plan.focus}",
        f"- Strategy: {plan.strategy} ({matched_text}).",
    ]
    if plan.check_control_plane:
        lines.append("- Run:ai control plane is in scope for this alert.")
    else:
        lines.append("- Run:ai control plane was ruled out of scope for this alert.")
    if plan.narrative:
        lines.append(f"- Approach: {plan.narrative}")
    alert = plan.matched_alert
    if alert:
        lines.append(
            f"- Documented Run:ai alert **{alert.get('alert')}** "
            f"({alert.get('severity', 'n/a')}) — {alert.get('trigger', '')}"
        )
        for step in alert.get("actions", [])[:5]:
            lines.append(f"  - {step}")
    return lines


def _best_evidence_line(result: CollectorResult) -> str:
    """The single most useful finding for this agent, not a status blurb."""
    if result.agent == "kubernetes":
        picked = _kubernetes_highlights(result.details)
    elif result.agent == "loki":
        picked = _loki_highlights(result.details)
    elif result.agent == "runai":
        picked = _runai_highlights(result.details)
    else:
        picked = []
    if picked:
        # highlight lines start with "- "; strip the marker for inline use.
        return picked[0].lstrip("- ").strip()
    return result.summary


def _kubernetes_highlights(details: dict[str, object]) -> list[str]:
    lines: list[str] = []
    warning_events = details.get("warning_events")
    if isinstance(warning_events, list):
        for event in warning_events[:3]:
            if not isinstance(event, dict):
                continue
            reason = event.get("reason") or "Warning"
            message = event.get("message") or ""
            if message:
                lines.append(
                    f"- Kubernetes event {reason}: "
                    f"{_short_sentence(str(message), limit=220)}"
                )
    pod_statuses = details.get("pod_statuses")
    if isinstance(pod_statuses, list):
        for pod in pod_statuses[:2]:
            if not isinstance(pod, dict):
                continue
            phase = pod.get("phase")
            name = pod.get("name")
            if phase and name:
                lines.append(f"- Kubernetes pod {name} is in phase {phase}.")
    return lines


def _loki_highlights(details: dict[str, object]) -> list[str]:
    lines: list[str] = []
    queries = details.get("queries")
    if not isinstance(queries, list):
        return lines
    for query in queries:
        if not isinstance(query, dict):
            continue
        line_count = query.get("line_count")
        name = query.get("name") or "query"
        if isinstance(line_count, int) and line_count > 0:
            lines.append(f"- Loki {name} returned {line_count} matching log line(s).")
    return lines


def _runai_highlights(details: dict[str, object]) -> list[str]:
    lines: list[str] = []
    project = details.get("project")
    workload = details.get("workload_name") or details.get("runai_workload_id")
    if project or workload:
        lines.append(
            "- Run:ai target context: "
            f"project={project or 'unknown'}, workload={workload or 'unknown'}."
        )
    queries = details.get("queries")
    if isinstance(queries, list):
        for query in queries[:3]:
            if not isinstance(query, dict):
                continue
            if query.get("error"):
                lines.append(
                    "- Run:ai "
                    f"{query.get('name', 'query')} failed with {query.get('error')}."
                )
    return lines


_SIMILARITY_FLOOR = 0.80


def _recommended_action_lines(
    missing: list[str], request: AlertAnalysisRequest | None = None
) -> list[str]:
    # Concrete actions only — no generic "trust the evidence" filler.
    lines: list[str] = []
    # Weave the proven RCA/fix from a high-similarity past incident into the actions.
    top = _top_similar_incident(request) if request else None
    if top is not None:
        proven = (top.analysis_summary or top.title or "").strip()
        if proven:
            lines.append(
                f"- Similar past incident {top.incident_id} (similarity "
                f"{top.similarity:.2f}) was resolved by: {proven} — verify this fix "
                "applies here before repeating it."
            )
    if "runai.auth" in missing or "runai.query" in missing:
        lines.append(
            "- Restore Run:ai API authentication so the agent can attach "
            "workload/project context on the next analysis run."
        )
    if "loki.auth" in missing or "loki.query" in missing:
        lines.append(
            "- Fix Loki reachability for the next analysis run: prefer the direct "
            "loki-read service, and only add tenant/auth settings when the endpoint "
            "explicitly requires them."
        )
    if "postgres.query" in missing or "postgres.connection" in missing:
        lines.append(
            "- Restore Postgres connectivity so RCA memory and similar-incident "
            "evidence stay current."
        )
    return lines


async def _operator_questions(
    settings: Settings,
    missing: list[str],
    plan: InvestigationPlan | None,
    target: AnalysisTarget,
    next_check: str,
) -> list[str]:
    """2-4 concrete follow-up questions when the RCA could not settle.

    Derived deterministically from missing_data + the plan; the LLM only sharpens
    the wording when configured (deterministic list is the fallback).
    """
    ko = getattr(settings, "language", "en") == "ko"

    def has(prefix: str) -> bool:
        return any(item.startswith(prefix) for item in missing)

    questions: list[str] = []
    if next_check:
        questions.append(next_check)
    if has("loki."):
        questions.append(
            "Loki 주소(LOKI_URL)가 설정되어 있고 에이전트에서 접근 가능한지 확인해 주세요."
            if ko
            else "Is the Loki URL configured and reachable from the agent?"
        )
    if has("runai."):
        questions.append(
            "Run:ai API 인증 정보(토큰 또는 클라이언트 ID/시크릿)가 유효한지 확인해 주세요."
            if ko
            else "Are the Run:ai API credentials (token or client id/secret) still valid?"
        )
    if has("prometheus."):
        questions.append(
            "Prometheus 주소(PROMETHEUS_URL)가 설정되어 있는지 확인해 주세요."
            if ko
            else "Is the Prometheus URL configured for the agent?"
        )
    if has("postgres."):
        questions.append(
            "Postgres 연결 정보(DSN)가 설정되어 있는지 확인해 주세요."
            if ko
            else "Is the Postgres DSN configured so RCA memory can be consulted?"
        )
    if has("kubernetes."):
        questions.append(
            "에이전트의 Kubernetes 서비스 계정 토큰이 유효한지 확인해 주세요."
            if ko
            else "Is the agent's Kubernetes service-account token valid?"
        )
    namespaces = list(plan.namespaces) if plan else []
    if has("system_agent.") or not (target.namespace or namespaces):
        questions.append(
            "이 알림이 발생한 노드에 접근(시스템 에이전트 등)이 가능한지 확인해 주세요."
            if ko
            else "Is the node this alert fired on accessible (system agent or SSH)?"
        )
    if len(questions) < 2:
        questions.append(
            "알림 발생 시각 전후에 배포나 설정 변경이 있었는지 확인해 주세요."
            if ko
            else "Were there any deployments or config changes around the alert time?"
        )
    questions = questions[:4]

    if llm_configured(settings):
        try:
            sharpened = await _sharpen_operator_questions(settings, questions, missing, plan)
        except Exception:  # noqa: BLE001 - sharpening is best-effort
            sharpened = None
        if sharpened:
            return sharpened
    return questions


async def _sharpen_operator_questions(
    settings: Settings,
    questions: list[str],
    missing: list[str],
    plan: InvestigationPlan | None,
) -> list[str] | None:
    """LLM-sharpened operator questions; None keeps the deterministic list."""
    ko = getattr(settings, "language", "en") == "ko"
    system = (
        "You review operator-facing follow-up questions for an RCA that could not "
        "settle on a root cause. Rewrite the draft questions to be sharper and more "
        "specific to the missing data and investigation plan. Do not invent facts, "
        "do not add generic filler. "
        + ("반드시 한국어로 작성하세요. " if ko else "Write in English. ")
        + 'Respond with ONLY JSON: {"questions": [str, ...]} containing 2 to 4 questions.'
    )
    user = json.dumps(
        {
            "draft_questions": questions,
            "missing_data": missing,
            "plan": plan.as_dict() if plan else {},
        },
        ensure_ascii=False,
        default=str,
    )
    data = await complete_json(settings, system=system, user=user, temperature=0.2)
    if not isinstance(data, dict):
        return None
    raw = data.get("questions")
    if not isinstance(raw, list):
        return None
    cleaned = [str(item).strip() for item in raw if str(item).strip()]
    if 2 <= len(cleaned) <= 4:
        return cleaned
    return None


# Xid codes appear as "Xid 79", "Xid: 79", or "NVRM: Xid (PCI:0000:3b:00): 79" —
# skip the optional parenthesized PCI address before the code so we don't capture it.
_XID_PATTERN = re.compile(
    r"\bxid\s*(?:\([^)]*\))?\s*[:=]?\s*(\d{1,4})", re.IGNORECASE
)


def _xid_codes_from_results(results: list[CollectorResult]) -> list[int]:
    """Distinct NVIDIA Xid codes found in loki/system/kubernetes evidence."""
    codes: list[int] = []
    for result in results:
        if result.agent not in ("loki", "system", "kubernetes"):
            continue
        text = _stringify_result(result)
        for match in _XID_PATTERN.finditer(text):
            code = int(match.group(1))
            if code not in codes:
                codes.append(code)
    return codes


def _gpu_model_from(target: AnalysisTarget, results: list[CollectorResult]) -> str:
    """GPU model, when a collector resolved one into its details (e.g. gpu_model)."""
    for result in results:
        for key in ("gpu_model", "gpu_type", "gpu_product"):
            value = result.details.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _stringify_result(result: CollectorResult) -> str:
    parts = [result.summary or ""]
    if result.details:
        try:
            parts.append(json.dumps(result.details, default=str))
        except (TypeError, ValueError):
            parts.append(str(result.details))
    return " ".join(parts)


def _graph_remediation_lines(graph_fixes: GraphRemediation | None) -> list[str]:
    if graph_fixes is None or graph_fixes.is_empty():
        return []
    lines = ["- Knowledge-graph derived remediation:"]
    for statement in graph_fixes.family_fixes[:5]:
        lines.append(f"  - {statement}")
    for code, fixes in graph_fixes.xid_fixes.items():
        lines.append(f"  - NVIDIA Xid {code}:")
        lines.extend(f"    - {statement}" for statement in fixes[:5])
    for model, xids in graph_fixes.model_xids.items():
        rendered = ", ".join(str(x) for x in xids)
        lines.append(f"  - Known Xid codes for {model}: {rendered}.")
    return lines


def _affected_pods_lines(request: AlertAnalysisRequest) -> list[str]:
    pods = [pod.strip() for pod in request.occurrence_pods if pod and pod.strip()]
    count = request.occurrence_count
    if not pods and count <= 1:
        return []
    lines = ["", "### Affected Pods", ""]
    if count > 1:
        lines.append(
            f"- This alert was grouped from {count} occurrence(s) of the same workload; "
            "the controller keeps recreating pods under new names, so treat the names "
            "below as one cycling workload rather than separate failures."
        )
    if pods:
        shown = pods[:20]
        lines.extend(f"- `{pod}`" for pod in shown)
        if len(pods) > len(shown):
            lines.append(f"- … and {len(pods) - len(shown)} more pod(s)")
    else:
        lines.append("- Individual pod names were not present on the alert labels.")
    return lines


def _top_similar_incident(request: AlertAnalysisRequest):
    """Highest-similarity incident at/above the 0.80 trust floor, else None."""
    qualified = [
        item
        for item in request.similar_incidents
        if (item.similarity or 0) >= _SIMILARITY_FLOOR
    ]
    if not qualified:
        return None
    return max(qualified, key=lambda item: item.similarity or 0)


def _similar_incident_lines(request: AlertAnalysisRequest) -> list[str]:
    lines = ["", "### Similar Incidents", ""]
    # Only surface vector hits we actually trust; a 0.70 "match" is noise.
    qualified = sorted(
        (i for i in request.similar_incidents if (i.similarity or 0) >= _SIMILARITY_FLOOR),
        key=lambda i: i.similarity or 0,
        reverse=True,
    )
    if not qualified:
        return [*lines, "- No similar past incident found."]
    for item in qualified[:3]:
        feedback = (
            f"{item.positive_feedback} up / {item.negative_feedback} down / "
            f"{item.comment_count} comments"
        )
        lines.append(
            f"- {item.incident_id} ({item.similarity:.3f}, {feedback}): "
            f"{item.analysis_summary or item.title}"
        )
    return lines


def _feedback_hint_lines(request: AlertAnalysisRequest) -> list[str]:
    lines = ["", "### Feedback Learning Hints", ""]
    if not request.feedback_hints:
        return [*lines, "- No operator feedback hints were provided."]
    for hint in request.feedback_hints[:5]:
        lines.append(f"- {hint.sentiment} from {hint.source_id}: {hint.text}")
    return lines


def _chat_answer_from_context(
    request: ChatRequest,
    context: dict[str, object],
    entity: str,
    masker: Masker,
) -> str:
    question = masker.mask_text(request.message.strip())
    incident_content = masker.mask_text((request.incident_content or "").strip())
    alert_content = masker.mask_text((request.alert_content or "").strip())
    active_content = alert_content or incident_content
    title = request.alert_title or request.incident_title or str(entity)
    memory = context.get("rca_memory")
    similar = context.get("similar_incidents")
    missing = _context_list(context, "missing_data")
    warnings = _context_list(context, "warnings")
    runtime_lines = _runtime_snapshot_lines(context)

    lines = [
        "## RCA Chat",
        "",
        f"**Context:** {title}",
        f"**Question:** {question}",
        "",
    ]
    if active_content:
        lines.extend(
            [
                "## Grounded Answer",
                "",
                _focused_chat_response(question, active_content),
                "",
            ]
        )
    else:
        if runtime_lines:
            lines.extend(
                [
                    "## Grounded Answer",
                    "",
                    "No incident or alert detail RCA text was attached, so I am answering from "
                    "the current Backend and Agent runtime state supplied with this chat request.",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "## Grounded Answer",
                    "",
                    "No incident, alert, analysis-run, or agent runtime state was attached to "
                    "this chat request. I cannot determine whether the agent is healthy, timed "
                    "out, or waiting for Alertmanager intake from this payload alone.",
                    "",
                ]
            )

    if runtime_lines:
        lines.extend(["## Current Agent State", "", *runtime_lines, ""])

    memory_lines = _memory_lines(memory or similar)
    if memory_lines:
        lines.extend(["## Related RCA Memory", "", *memory_lines, ""])
    if missing:
        lines.extend(["## Missing Data", "", *[f"- {item}" for item in missing[:8]], ""])
    if warnings:
        lines.extend(["## Warnings", "", *[f"- {item}" for item in warnings[:8]], ""])
    lines.extend(
        [
            "## Next Step",
            "",
            "Use the RCA detail and Agent Evidence Trail to confirm this against Run:AI, "
            "Kubernetes, Prometheus, Loki, and Postgres evidence before taking action.",
        ]
    )
    return "\n".join(lines)


def _runtime_snapshot_lines(context: dict[str, object]) -> list[str]:
    lines: list[str] = []
    dashboard = _dict_context(context.get("dashboard_state"))
    if dashboard:
        alert_count = dashboard.get("alert_count", 0)
        firing_alert_count = dashboard.get("firing_alert_count", 0)
        run_count = dashboard.get("analysis_run_count", 0)
        statuses = dashboard.get("analysis_statuses")
        lines.append(
            "- Backend dashboard state: "
            f"{alert_count} alert(s), {firing_alert_count} active/firing alert(s), "
            f"{run_count} analysis run(s)."
        )
        if isinstance(statuses, dict) and statuses:
            rendered = ", ".join(f"{key}={value}" for key, value in sorted(statuses.items()))
            lines.append(f"- Analysis run status counts: {rendered}.")
        latest_alert = _dict_context(dashboard.get("latest_alert"))
        if latest_alert:
            lines.append(
                "- Latest alert: "
                f"{latest_alert.get('alert_id', 'unknown')} "
                f"({latest_alert.get('status', 'unknown')}, "
                f"{latest_alert.get('severity', 'unknown')}): "
                f"{latest_alert.get('title', 'untitled')}."
            )
            alert_warnings = _string_list(latest_alert.get("warnings"))
            if alert_warnings:
                lines.append(f"- Latest alert warnings: {_compact_inline(alert_warnings, 2)}.")
        latest_run = _dict_context(dashboard.get("latest_run"))
        if latest_run:
            lines.append(
                "- Latest analysis run: "
                f"{latest_run.get('run_id', 'unknown')} is "
                f"{latest_run.get('status', 'unknown')} "
                f"for {latest_run.get('target_type', 'target')} "
                f"{latest_run.get('target_id', 'unknown')}."
            )
            capabilities = _dict_context(latest_run.get("capabilities"))
            agent_status = capabilities.get("agent") if capabilities else None
            if agent_status:
                lines.append(f"- Latest backend-to-agent call status: {agent_status}.")
            run_warnings = _string_list(latest_run.get("warnings"))
            if run_warnings:
                lines.append(f"- Latest run warnings: {_compact_inline(run_warnings, 3)}.")
            missing = _string_list(latest_run.get("missing_data"))
            if missing:
                lines.append(f"- Latest run missing data: {_compact_inline(missing, 3)}.")

    backend_runtime = _dict_context(context.get("agent_runtime"))
    if backend_runtime:
        timeout = backend_runtime.get("agent_request_timeout_seconds")
        chat_mode = backend_runtime.get("chat_mode")
        if timeout or chat_mode:
            lines.append(
                "- Backend agent client: "
                f"timeout={timeout or 'unknown'}s, chat_mode={chat_mode or 'unknown'}."
            )
        database = _dict_context(backend_runtime.get("database"))
        if database:
            lines.append(
                "- Backend database state: "
                f"postgres={database.get('postgres')}, "
                f"pgvector_status={database.get('pgvector_status')}, "
                f"similarity_search={database.get('similarity_search')}."
            )

    agent_service = _dict_context(context.get("agent_service"))
    if agent_service:
        lines.append(
            "- Agent service runtime: "
            f"nemo_runtime={agent_service.get('nemo_runtime')}, "
            f"chat_mode={agent_service.get('chat_mode')}, "
            f"llm_configured={agent_service.get('llm_configured')}."
        )
        integrations = []
        for key in [
            "runai_configured",
            "prometheus_configured",
            "loki_configured",
            "postgres_configured",
        ]:
            integrations.append(f"{key.replace('_configured', '')}={agent_service.get(key)}")
        lines.append("- Agent integration config: " + ", ".join(integrations) + ".")

    return lines


def _dict_context(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _compact_inline(items: list[str], limit: int) -> str:
    selected = items[:limit]
    rendered = "; ".join(_compact_text(item, 220) for item in selected)
    if len(items) > limit:
        rendered += f"; +{len(items) - limit} more"
    return rendered


def _focused_chat_response(question: str, content: str) -> str:
    lowered = question.lower()
    excerpted = _compact_text(content, 1800)
    if any(word in lowered for word in ["action", "recommend", "next", "해야", "조치"]):
        return (
            "The recommended path should follow the RCA's evidence-backed remediation actions. "
            f"Relevant RCA context:\n\n{excerpted}"
        )
    if any(word in lowered for word in ["evidence", "why", "근거", "왜"]):
        return (
            "The strongest answer should come from the attached evidence and missing-data list. "
            f"Relevant RCA context:\n\n{excerpted}"
        )
    if any(word in lowered for word in ["similar", "previous", "past", "유사", "이전"]):
        return (
            "Compare this incident with the related RCA memory below, "
            "then verify against live evidence. "
            f"Current RCA context:\n\n{excerpted}"
        )
    return f"Based on the attached RCA context:\n\n{excerpted}"


def _memory_lines(memory: object) -> list[str]:
    if not isinstance(memory, list):
        return []
    lines: list[str] = []
    for item in memory[:5]:
        if not isinstance(item, dict):
            continue
        incident_id = item.get("incident_id") or item.get("IncidentID") or "unknown"
        summary = item.get("analysis_summary") or item.get("AnalysisSummary") or item.get("title")
        similarity = item.get("similarity") or item.get("Similarity")
        if summary:
            lines.append(f"- {incident_id} ({similarity or 'memory'}): {summary}")
    return lines


def _context_list(context: dict[str, object], key: str) -> list[str]:
    value = context.get(key)
    if value is None and isinstance(context.get("incident"), dict):
        value = context["incident"].get(key)  # type: ignore[index]
    if value is None and isinstance(context.get("alert"), dict):
        value = context["alert"].get(key)  # type: ignore[index]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _compact_text(value: str, limit: int) -> str:
    cleaned = "\n".join(line.rstrip() for line in value.splitlines() if line.strip())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit].rstrip() + "\n\n[context truncated]"
