from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import TypeVar
from uuid import uuid4

from pydantic import BaseModel

from app.collectors.base import CollectorResult, resolve_target
from app.collectors.http_json import post_json
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.config import Settings
from app.knowledge import load_failure_modes, load_troubleshooting_cases
from app.masking import Masker, build_masker
from app.prompts import agent_role_coverage_lines, load_agent_souls
from app.schemas import (
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    ChatRequest,
    ChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
)
from app.services.kg_enrichment import enrich
from app.services.root_cause_ranking import RankedCause, rank_root_cause_candidates

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
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self._settings.nat_timeout_seconds
                )
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
            "__RUNAI_RCA_LLM_REQUEST_TIMEOUT_SECONDS__": str(
                self._settings.llm_request_timeout_seconds
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
        ]

    async def analyze(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        target = resolve_target(request.alert.labels, request.alert.annotations)
        # Knowledge graph is consulted once here, at synthesis time, as a
        # knowledge resource for the final RCA — not as a parallel collector.
        kg_context = await enrich(self._settings, target)
        nat_payload = request.model_dump(mode="json")
        nat_payload["mode"] = "alert_analysis"
        nat_payload["kg_context"] = kg_context.as_dict()
        agent_souls = load_agent_souls(self._settings.agent_souls_file)
        nat_payload["agent_souls"] = agent_souls
        nat_text = None
        nat_warnings: list[str] = []
        try:
            nat_text = await self._nat.run(nat_payload)
        except Exception as exc:
            nat_warnings.append(_unexpected_runtime_warning("nemo", exc))

        results = await asyncio.gather(
            *(_collect_safely(collector, target) for collector in self._collectors)
        )

        capabilities = {result.agent: result.status for result in results}
        artifacts = [artifact for result in results for artifact in result.artifacts]
        missing = sorted({item for result in results for item in result.missing_data})
        warnings = sorted(
            {item for result in results for item in result.warnings}
            | set(nat_warnings)
            | set(kg_context.warnings)
        )
        root_cause_candidates = rank_root_cause_candidates(
            target,
            results,
            occurrence_count=request.occurrence_count,
            kg_blast_radius=kg_context.blast_radius_workloads,
        )
        quality = _quality_from(results)
        summary = _summary_from(request, results, root_cause_candidates)
        failure_modes = load_failure_modes(self._settings.failure_modes_file)
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
        )

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


def _quality_from(results: list[CollectorResult]) -> str:
    counts = Counter(result.status for result in results)
    if counts["ok"] >= 3:
        return "high"
    if counts["ok"] >= 1 or counts["partial"] >= 2:
        return "medium"
    return "low"


async def _collect_safely(collector: object, target: object) -> CollectorResult:
    try:
        return await collector.collect(target)  # type: ignore[attr-defined]
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


def _detail_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    missing: list[str],
    failure_modes: dict[str, list[dict]] | None = None,
    troubleshooting_cases: str = "",
    agent_souls: str = "",
    root_cause_candidates: list[RankedCause] | None = None,
    kg_context: dict | None = None,
) -> str:
    labels = request.alert.labels
    annotations = request.alert.annotations
    root_cause = _ranked_root_cause_statement(root_cause_candidates or [], request)
    lines = [
        "## Root Cause",
        "",
        root_cause,
        "",
        "The agent checked the configured Run:ai, Kubernetes, Prometheus, Loki, "
        "and Postgres collectors for this RCA. Confirmed evidence and missing "
        "collector data are listed below.",
    ]
    lines.extend(_affected_pods_lines(request))
    lines.extend(
        [
            "",
            "## Evidence",
            "",
        ]
    )
    for result in results:
        lines.append(f"- **{result.agent}**: {result.summary}")
    highlight_lines = _evidence_highlight_lines(results)
    if highlight_lines:
        lines.extend(["", "## Evidence Highlights", "", *highlight_lines])
    lines.extend(
        _knowledge_base_lines(kg_context, root_cause_candidates, _observed_text(results))
    )
    operator_prompt = annotations.get("operator_prompt")
    if operator_prompt:
        lines.extend(
            [
                "",
                "## Operator Guidance",
                "",
                operator_prompt,
            ]
        )
    lines.extend(
        [
            "",
            "## Agent Role Coverage",
            "",
        ]
    )
    lines.extend(agent_role_coverage_lines())
    if not agent_souls:
        lines.append("- Agent role contract file was not loaded; fallback guidance was used.")
    lines.extend(
        [
            "",
            "## Recommended Actions",
            "",
            *_recommended_action_lines(missing),
            "",
            "## Troubleshooting Playbook",
            "",
        ]
    )
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
            "## Alert Labels",
            "",
            "```json",
            json.dumps(labels, indent=2, sort_keys=True),
            "```",
        ]
    )
    return "\n".join(lines)


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
    return ["", "## Knowledge Base (Ontology)", "", *body]


def _kb_remediation_lines(
    kg_context: dict, candidates: list[RankedCause] | None, observed_text: str
) -> list[str]:
    knowledge = kg_context.get("knowledge") or {}
    if not candidates or not knowledge:
        return []
    top_family = candidates[0].family
    symptoms = knowledge.get(top_family) or []
    if not symptoms:
        return []
    text = observed_text.lower()
    # Precise: the first symptom whose keyword appears in the observed evidence.
    for symptom in symptoms:
        if any(str(kw).lower() in text for kw in symptom.get("keywords", [])):
            actions = symptom.get("actions", [])
            if actions:
                header = (
                    f"- Known fixes for **{symptom.get('symptom')}** "
                    f"({top_family}, from the knowledge base):"
                )
                return [header, *[f"  - {a}" for a in actions[:5]]]
    # Fallback: no specific symptom matched -> the family's actions.
    fallback = sorted({a for symptom in symptoms for a in symptom.get("actions", [])})
    if not fallback:
        return []
    header = f"- Known fixes for **{top_family}** (from the knowledge base):"
    return [header, *[f"  - {a}" for a in fallback[:5]]]


def _playbook_lines(
    candidates: list[RankedCause] | None,
    observed_text: str,
    failure_modes: dict[str, list[dict]],
    fallback_cases: str,
) -> list[str]:
    """Root-cause-relevant remediation, keyed to the top-ranked family.

    Shows the curated fixes for the identified family (precise when a symptom
    keyword matches the observed evidence, otherwise the family checklist). Only
    when no family is confidently ranked does it fall back to the full case library.
    """
    top_family = candidates[0].family if candidates else ""
    symptoms = failure_modes.get(top_family) if top_family else None
    if not symptoms:
        if fallback_cases:
            return [fallback_cases]
        return ["- No troubleshooting guidance is available for this cause yet."]
    text = (observed_text or "").lower()
    lines = [f"Guidance for the most likely cause: **{_family_label(top_family)}**.", ""]
    matched = False
    for symptom in symptoms:
        if any(kw in text for kw in symptom.get("keywords", [])):
            matched = True
            lines.append(f"- **{symptom.get('symptom')}**")
            lines.extend(f"  - {action}" for action in symptom.get("actions", [])[:5])
    if not matched:
        actions = sorted({a for s in symptoms for a in s.get("actions", [])})
        lines.extend(f"- {action}" for action in actions[:6])
    return lines


def _family_label(family: str) -> str:
    labels = {
        "node_kubelet_pressure": "node kubelet pressure",
        "scheduling_quota_exhaustion": "scheduling quota exhaustion",
        "control_plane_error": "Run:ai control-plane error",
        "workload_startup_image_failure": "workload startup/image failure",
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


def _evidence_highlight_lines(results: list[CollectorResult]) -> list[str]:
    lines: list[str] = []
    for result in results:
        if result.agent == "kubernetes":
            lines.extend(_kubernetes_highlights(result.details))
        elif result.agent == "loki":
            lines.extend(_loki_highlights(result.details))
        elif result.agent == "runai":
            lines.extend(_runai_highlights(result.details))
    return lines[:8]


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


def _recommended_action_lines(missing: list[str]) -> list[str]:
    lines = [
        "- Treat the Kubernetes and Prometheus evidence above as the current "
        "source of truth for this RCA.",
        "- Apply the remediation implied by the confirmed scheduling, pod, node, "
        "or metric evidence.",
    ]
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


def _affected_pods_lines(request: AlertAnalysisRequest) -> list[str]:
    pods = [pod.strip() for pod in request.occurrence_pods if pod and pod.strip()]
    count = request.occurrence_count
    if not pods and count <= 1:
        return []
    lines = ["", "## Affected Pods", ""]
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


def _similar_incident_lines(request: AlertAnalysisRequest) -> list[str]:
    lines = ["", "## Similar Incidents", ""]
    if not request.similar_incidents:
        return [*lines, "- No similar incident memory was provided."]
    for item in request.similar_incidents[:3]:
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
    lines = ["", "## Feedback Learning Hints", ""]
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
