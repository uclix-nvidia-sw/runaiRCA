from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from uuid import uuid4

from app.collectors.base import resolve_target
from app.collectors.registry import build_collectors
from app.config import Settings
from app.knowledge import load_failure_modes, load_runai_known_issues
from app.llm import (
    begin_usage_tracking,
    complete_with_error,
    llm_configured,
    reset_analysis_deadline,
    set_analysis_deadline,
    usage_with_cost,
)
from app.masking import Masker
from app.schemas import (
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    ChatRequest,
    ChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
)
from app.services import pipeline
from app.services.general_guidance import general_guidance_lines
from app.services.pipeline import (
    _build_settings_masker,
    _mask_model,
    _short_sentence,
    _unexpected_runtime_warning,
)

_log = logging.getLogger(__name__)


class AnalysisOrchestrator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._masker = _build_settings_masker(settings)
        self._collectors = build_collectors(settings)
        self._engine = None
        # NAT engine runtime health, edge-logged: "disabled" (off), "unknown"
        # (on, not yet exercised), "ok" (a run went through the engine), "failed"
        # (build/run threw; analyses silently fall back to the direct pipeline).
        # All updates run on the single asyncio loop thread, so no lock is needed.
        self._engine_state = "disabled" if not settings.enable_nat_runtime else "unknown"
        self._engine_last_error = ""
        self._engine_last_error_at = ""
        self._engine_last_ok_at = ""
        self._engine_consecutive_failures = 0

    async def start_engine(self) -> None:
        if not self._settings.enable_nat_runtime:
            return
        try:
            if self._engine is None:
                from app.nat_engine import NatEngine

                self._engine = NatEngine(self._settings)
            await self._engine.start()
        except Exception as exc:  # noqa: BLE001 - startup is best-effort; analyze falls back
            self._record_engine_failure(exc)

    async def close_engine(self) -> None:
        engine = self._engine
        if engine is None:
            return
        await engine.aclose()

    def engine_health(self) -> dict[str, object]:
        """Runtime NAT-engine health for /healthz. Pure state read — never logs,
        so kubelet probes don't spam the log."""
        return {
            "enabled": self._settings.enable_nat_runtime,
            "state": self._engine_state,
            "consecutive_failures": self._engine_consecutive_failures,
            "last_error": self._engine_last_error,
            "last_error_at": self._engine_last_error_at,
            "last_ok_at": self._engine_last_ok_at,
        }

    def _record_engine_ok(self) -> None:
        now = datetime.now(UTC).isoformat()
        if self._engine_state == "failed":  # edge only: recovery
            _log.info("nemo engine recovered at %s", now)
        self._engine_state = "ok"
        self._engine_last_ok_at = now
        self._engine_consecutive_failures = 0

    def _record_engine_failure(self, exc: object) -> None:
        now = datetime.now(UTC).isoformat()
        masked_error = self._masker.mask_text(str(exc))
        if self._engine_state != "failed":  # edge only: first failure after healthy
            _log.error(
                "nemo engine FAILING since %s; analyses fall back to the direct "
                "pipeline (LLM synthesis off). Check the engine config/LLM endpoint: %s",
                now,
                masked_error,
            )
        self._engine_state = "failed"
        self._engine_last_error = masked_error
        self._engine_last_error_at = now
        self._engine_consecutive_failures += 1

    async def analyze(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        """Run one analysis under an overall hard deadline.

        Per-step ceilings (collectors, LLM, NAT) are generous so agents gather deep
        evidence and think; this wrapper guarantees the whole run still finishes
        within `analysis_deadline_seconds` (default 25 min / 1500s), returning a
        terminal degraded report if it overruns rather than hanging."""
        usage = begin_usage_tracking()
        deadline = self._settings.analysis_deadline_seconds
        started_at = time.monotonic()
        impl_kwargs = (
            {"analysis_started_at": started_at}
            if pipeline._accepts_keyword(self._analyze_impl, "analysis_started_at")
            else {}
        )
        if not deadline or deadline <= 0:
            response = await self._analyze_impl(request, **impl_kwargs)
            if isinstance(getattr(response, "context", None), dict):
                response.context["llm_usage"] = self._usage_context(response, usage)
            return response
        # Stop LLM transports shortly before the public hard deadline so their
        # deterministic fallbacks can assemble and return the evidence already
        # collected instead of losing it to the outer wait_for cancellation.
        completion_margin = min(20.0, max(2.0, deadline * 0.01))
        token = set_analysis_deadline(started_at + deadline - completion_margin)
        try:
            response = await asyncio.wait_for(
                self._analyze_impl(request, **impl_kwargs), timeout=deadline
            )
        except TimeoutError:  # asyncio.TimeoutError is this builtin on 3.11+
            _log.warning("analysis exceeded the %ss deadline; returning degraded report", deadline)
            response = self._deadline_response(request, deadline)
        finally:
            reset_analysis_deadline(token)
        response.context["llm_usage"] = self._usage_context(response, usage)
        return response

    def _usage_context(self, response: AlertAnalysisResponse, usage: dict) -> dict:
        usage_context = usage_with_cost(self._settings, usage)
        nat_usage = response.context.pop("llm_usage_nat", None)
        if nat_usage:
            usage_context["nat"] = nat_usage
        return usage_context

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
            status="failed",
            terminal_reason="deadline_exceeded",
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

    async def _analyze_impl(
        self, request: AlertAnalysisRequest, *, analysis_started_at: float | None = None
    ) -> AlertAnalysisResponse:
        nat_warning = None
        if self._settings.enable_nat_runtime:
            try:
                response = await self._engine_run(request)
            except Exception as exc:  # noqa: BLE001 - engine failure degrades, never breaks analysis
                self._record_engine_failure(exc)
                nat_warning = pipeline._unexpected_runtime_warning("nemo", exc, self._masker)
            else:
                incomplete = self._incomplete_engine_response_reason(response)
                if incomplete:
                    exc = RuntimeError(incomplete)
                    self._record_engine_failure(exc)
                    nat_warning = pipeline._unexpected_runtime_warning("nemo", exc, self._masker)
                else:
                    self._record_engine_ok()
                    return response
        state = pipeline.new_state(
            self._settings,
            request,
            collectors=self._collectors,
            analysis_started_at=analysis_started_at,
        )
        if nat_warning:
            state.extra_warnings.append(nat_warning)
        return await pipeline.run_pipeline(state)

    async def _engine_run(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        if self._engine is None:
            from app.nat_engine import NatEngine

            self._engine = NatEngine(self._settings)
        return await self._engine.run(request)

    def _incomplete_engine_response_reason(self, response: AlertAnalysisResponse) -> str:
        if not str(response.analysis_summary or "").strip():
            return "nemo engine returned an incomplete RCA response: missing analysis_summary"
        if not str(response.analysis_detail or "").strip():
            return "nemo engine returned an incomplete RCA response: missing analysis_detail"
        context = response.context if isinstance(response.context, dict) else {}
        candidates = context.get("root_cause_candidates")
        if not isinstance(candidates, list) or not candidates:
            return "nemo engine returned an incomplete RCA response: missing root_cause_candidates"
        top = candidates[0]
        if not isinstance(top, dict) or not str(top.get("family") or "").strip():
            return (
                "nemo engine returned an incomplete RCA response: invalid top root-cause candidate"
            )
        top_context = context.get("top_root_cause")
        if not isinstance(top_context, dict) or top_context.get("family") != top.get("family"):
            return (
                "nemo engine returned an incomplete RCA response: "
                "top_root_cause does not match root_cause_candidates[0]"
            )
        return ""

    async def summarize_incident(self, request: IncidentSummaryRequest) -> IncidentSummaryResponse:
        alerts = request.alerts
        safe = lambda value, limit: _short_sentence(  # noqa: E731 - local formatting helper
            self._masker.mask_text(str(value or "-")), limit=limit
        )
        title = request.title if request.title and request.title != "Ongoing" else "Run:AI incident"
        title = safe(title, 180)
        summaries = [
            alert.analysis_summary
            for alert in alerts
            if alert.analysis_summary and alert.analysis_summary.strip()
        ]
        summary = (
            safe(summaries[0], 320) if summaries else f"{len(alerts)} alert(s) were correlated."
        )
        detail_lines = [
            "## Incident Summary",
            "",
            f"- Incident: {safe(request.incident_id, 120)}",
            f"- Severity: {safe(request.severity, 80)}",
            f"- Alert count: {len(alerts)}",
            f"- Window: {safe(request.fired_at, 120)} to {safe(request.resolved_at, 120)}",
            "",
            "## Alert Evidence",
        ]
        for alert in alerts:
            alert_summary = safe(alert.analysis_summary or "No analysis summary yet.", 320)
            detail_lines.append(
                f"- {safe(alert.alert_name, 120)} ({safe(alert.status, 40)}, "
                f"{safe(alert.severity, 40)}): {alert_summary}"
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
        chat_llm_configured = llm_configured(self._settings, self._settings.llm_model_chat)
        context["agent_service"] = {
            "nemo_runtime": "enabled" if self._settings.enable_nat_runtime else "fallback",
            "chat_mode": "llm" if chat_llm_configured else "deterministic_context",
            "chat_llm_runtime": "active" if chat_llm_configured else "not_directly_used",
            "llm_configured": chat_llm_configured,
            "nat_config_file": self._settings.nat_config_file,
            "runai_configured": bool(self._settings.runai_base_url),
            "runai_mcp_configured": bool(self._settings.runai_mcp_url),
            # MCP transports per domain — without these the chat honestly
            # concluded "kubernetes 전용 MCP는 구성되어 있지 않습니다" from an
            # incomplete config listing.
            "kubernetes_mcp_configured": bool(self._settings.kubernetes_mcp_url),
            "prometheus_mcp_configured": bool(self._settings.prometheus_mcp_url),
            "loki_mcp_configured": bool(self._settings.loki_mcp_url),
            "postgres_mcp_configured": bool(self._settings.postgres_mcp_url),
            "prometheus_configured": bool(self._settings.prometheus_url),
            "loki_configured": bool(self._settings.loki_url),
            "postgres_configured": bool(self._settings.postgres_dsn),
            "investigation_loop_enabled": bool(self._settings.enable_investigation_loop),
            "agent_drilldown_enabled": bool(self._settings.enable_agent_drilldown),
        }
        entity = (
            request.incident_id
            or request.alert_id
            or context.get("incident_id")
            or context.get("alert_id")
            or request.page
            or "current RCA workspace"
        )
        language = getattr(self._settings, "language", "en")
        grounding = _chat_answer_from_context(
            request,
            context,
            str(entity),
            self._masker,
            language=language,
            failure_modes=load_failure_modes(self._settings.failure_modes_file),
            known_issues=load_runai_known_issues(self._settings.runai_known_issues_file),
        )
        answer = grounding
        if chat_llm_configured:
            try:
                from app.services.chat_agent import answer_chat

                # Agentic chat: the copilot can run read-only cluster queries and
                # on-demand RCA, not just answer from the loaded workspace context.
                llm_answer, llm_error = await answer_chat(
                    self._settings, request, grounding, analyze_fn=self.analyze
                )
            except Exception as exc:
                warning = self._masker.mask_text(_unexpected_runtime_warning("llm", exc))
                answer = _append_chat_warning(grounding, warning, language)
            else:
                if llm_answer:
                    answer = self._masker.mask_text(llm_answer)
                else:
                    # LLM path failed: fall back to the context dump but SAY SO —
                    # a silent English dump reads like a broken chatbot.
                    note = (
                        f"LLM 채팅 호출이 실패하여 컨텍스트 요약으로 대신 답합니다 ({llm_error})."
                        if language == "ko"
                        else (
                            f"The LLM chat call failed ({llm_error}); "
                            "showing the grounded context instead."
                        )
                    )
                    answer = _append_chat_warning(grounding, self._masker.mask_text(note), language)
        response = ChatResponse(
            status="ok",
            answer=answer,
            message=answer,
            response=answer,
            conversation_id=request.conversation_id or f"chat-{uuid4().hex[:10]}",
        )
        return _mask_model(response, ChatResponse, self._masker)

    async def _llm_chat_answer(
        self, request: ChatRequest, grounding: str
    ) -> tuple[str | None, str | None]:
        """(answer, error_detail). The error is surfaced to the operator so an
        LLM failure never silently degrades into the context dump."""
        question = (request.message or "").strip()
        if not question:
            return None, "empty question"
        masker = getattr(self, "_masker", None)
        if masker is not None:
            question = masker.mask_text(question)
            grounding = masker.mask_text(grounding)
        language_rule = (
            "반드시 한국어로 답변하세요."
            if getattr(self._settings, "language", "en") == "ko"
            else "Reply in the operator's language."
        )
        system = (
            "You are the RCA copilot for an NVIDIA Run:AI GPU platform. Answer the operator's "
            "question DIRECTLY and concisely, using the grounded context provided. Lead with "
            "the answer to the question itself — do not recite the context. If the context "
            f"lacks the answer, say so and suggest the next diagnostic step. {language_rule}"
        )
        answer, error = await complete_with_error(
            self._settings,
            system=system,
            user=f"Grounded context:\n{grounding}\n\nQuestion: {question}",
            temperature=0.2,
            model=getattr(self._settings, "llm_model_chat", ""),
        )
        return answer, error


def _append_chat_warning(answer: str, warning: str, language: str = "en") -> str:
    heading = "## 경고" if language == "ko" else "## Warnings"
    for existing in ("## Warnings", "## 경고"):
        if existing in answer:
            return f"{answer}\n- {warning}"
    return "\n".join([answer, "", heading, "", f"- {warning}"])


# Deterministic chat scaffold strings, localized: the operator-facing fallback
# must follow settings.language like the reports do.
_CHAT_STRINGS = {
    "en": {
        "title": "## RCA Chat",
        "context": "**Context:**",
        "question": "**Question:**",
        "answer": "## Grounded Answer",
        "no_detail": (
            "No incident or alert detail RCA text was attached, so I am answering from "
            "the current Backend and Agent runtime state supplied with this chat request."
        ),
        "no_state": (
            "No incident, alert, analysis-run, or agent runtime state was attached to "
            "this chat request. I cannot determine whether the agent is healthy, timed "
            "out, or waiting for Alertmanager intake from this payload alone."
        ),
        "state": "## Current Agent State",
        "memory": "## Related RCA Memory",
        "missing": "## Missing Data",
        "warnings": "## Warnings",
        "next": "## Next Step",
        "general": "## General Troubleshooting Guidance",
        "next_body": (
            "Use the RCA detail and Agent Evidence Trail to confirm this against Run:AI, "
            "Kubernetes, Prometheus, Loki, and Postgres evidence before taking action."
        ),
    },
    "ko": {
        "title": "## RCA 챗",
        "context": "**컨텍스트:**",
        "question": "**질문:**",
        "answer": "## 근거 기반 답변",
        "no_detail": (
            "이 채팅 요청에 인시던트/알림 상세 RCA 본문이 첨부되지 않아, 함께 전달된 "
            "백엔드·에이전트 런타임 상태를 기준으로 답합니다."
        ),
        "no_state": (
            "이 채팅 요청에는 인시던트, 알림, 분석 실행, 에이전트 런타임 상태가 첨부되지 "
            "않았습니다. 이 페이로드만으로는 에이전트의 상태(정상/타임아웃/수집 대기)를 "
            "판단할 수 없습니다."
        ),
        "state": "## 현재 에이전트 상태",
        "memory": "## 관련 RCA 메모리",
        "missing": "## 누락된 데이터",
        "warnings": "## 경고",
        "next": "## 다음 단계",
        "general": "## 일반 점검 가이드",
        "next_body": (
            "조치 전에 RCA 상세와 Agent Evidence Trail에서 Run:AI, Kubernetes, "
            "Prometheus, Loki, Postgres 증거로 이 내용을 확인하세요."
        ),
    },
}


def _chat_answer_from_context(
    request: ChatRequest,
    context: dict[str, object],
    entity: str,
    masker: Masker,
    language: str = "en",
    failure_modes: dict[str, list[dict[str, object]]] | None = None,
    known_issues: list[dict[str, object]] | None = None,
) -> str:
    text = _CHAT_STRINGS.get(language, _CHAT_STRINGS["en"])
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
        text["title"],
        "",
        f"{text['context']} {title}",
        f"{text['question']} {question}",
        "",
    ]
    if active_content:
        lines.extend(
            [
                text["answer"],
                "",
                _focused_chat_response(question, active_content),
                "",
            ]
        )
    else:
        lines.extend(
            [
                text["answer"],
                "",
                text["no_detail"] if runtime_lines else text["no_state"],
                "",
                text["general"],
                "",
                *general_guidance_lines(
                    question,
                    failure_modes or {},
                    known_issues or [],
                    language=language,
                    masker=masker,
                ),
                "",
            ]
        )

    if runtime_lines:
        lines.extend([text["state"], "", *runtime_lines, ""])

    memory_lines = _memory_lines(memory or similar, masker)
    if memory_lines:
        lines.extend([text["memory"], "", *memory_lines, ""])
    if missing:
        lines.extend([text["missing"], "", *[f"- {item}" for item in missing[:8]], ""])
    if warnings:
        lines.extend([text["warnings"], "", *[f"- {item}" for item in warnings[:8]], ""])
    lines.extend([text["next"], "", text["next_body"]])
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
            "runai_mcp_configured",
            "kubernetes_mcp_configured",
            "prometheus_mcp_configured",
            "loki_mcp_configured",
            "postgres_mcp_configured",
            "prometheus_configured",
            "loki_configured",
            "postgres_configured",
        ]:
            integrations.append(f"{key.replace('_configured', '')}={agent_service.get(key)}")
        lines.append("- Agent integration config: " + ", ".join(integrations) + ".")
        lines.append(
            "- Agent reasoning config: "
            f"investigation_loop={agent_service.get('investigation_loop_enabled')}, "
            f"agent_drilldown={agent_service.get('agent_drilldown_enabled')}."
        )

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


def _memory_lines(memory: object, masker: Masker) -> list[str]:
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
            rendered_id = _short_sentence(masker.mask_text(str(incident_id)), limit=80)
            rendered_similarity = _short_sentence(
                masker.mask_text(str(similarity or "memory")), limit=40
            )
            rendered_summary = _short_sentence(masker.mask_text(str(summary)), limit=320)
            lines.append(f"- {rendered_id} ({rendered_similarity}): {rendered_summary}")
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
