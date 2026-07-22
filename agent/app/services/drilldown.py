"""Per-collector autonomous drill-down loops (LLM-gated, read-only).

Each evidence agent (kubernetes / prometheus / loki / runai) runs its OWN small
bounded LLM loop after the base gather: it looks at ITS OWN evidence and decides
follow-up read-only queries in ITS OWN domain. Tool scoping is structural — each
loop receives only its domain's tool registry, so the kubernetes loop cannot
call the Run:ai API and vice versa. Follow-up results are appended to the
collector's artifacts, where the existing pipeline (masking, signature matching,
the verify pass, synthesis) consumes them with zero changes.

Best-effort like the central investigation loop: flag off (ENABLE_AGENT_DRILLDOWN),
no LLM, or ANY failure -> the base evidence stands. A loop runs at most
MAX_INVESTIGATION_STEPS reasoning rounds (three by default) and can end earlier
on `done`, a repeated query, or the analysis-wide deadline. Read-only by
construction: the k8s tool is the allowlisted `k8s_read`, Run:ai calls use only
the NVIDIA MCP server's focused read-only tools, PromQL/LogQL only hit query
endpoints, and SQL is a single SELECT inside a READ ONLY transaction
(RUNAI_DB_DSN lets the postgres agent query the Run:ai control-plane DB itself,
not just health-check the RCA store). Untrusted
log/event text feeds these loops, so the PROMPT_INJECTION_GUARD in app.llm rides
on every decision.

Operator-facing output: every follow-up lands as an artifact with a human title
("파드 조회"), the REAL query an operator would run (kubectl / PromQL / LogQL /
SQL), a finding-first summary, and `highlights` (base.salient_markers) the UI
marks in red.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from app.collectors.base import (
    NO_EVIDENCE,
    AnalysisTarget,
    CollectorResult,
    artifact,
    causal_evidence_time_range,
    incident_time_range,
    ko_en,
    kubernetes_salient_markers,
    salient_markers,
    signals_line,
)
from app.collectors.change import change_query
from app.collectors.http_json import get_json
from app.collectors.kubernetes import (
    _READ_KINDS,
    k8s_describe,
    k8s_exec,
    k8s_logs,
    k8s_read,
    kind_lookup_title,
    kubectl_repr,
    pod_inspection_repr,
    resolve_read_kind,
)
from app.collectors.loki import (
    _loki_headers,
    _loki_line_affirms_failure,
    _loki_native_response_complete,
    _loki_streams,
    _sample_lines,
    loki_mcp_query,
)
from app.collectors.prometheus import prom_mcp_query, prom_query
from app.collectors.runai_mcp import _tool_json, valid_official_workload_id
from app.collectors.system import system_log_query
from app.config import Settings
from app.llm import complete_json, complete_with_error, llm_configured
from app.masking import build_masker
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tls_verify,
    mcp_tool_json,
)
from app.plan import InvestigationPlan
from app.services.evidence_projection import observed_payload
from app.services.probe_evaluation import evaluate_probe
from app.services.query_memory import QueryMemory, domain_query_key

_log = logging.getLogger(__name__)

_RESULT_CHARS = 1500  # per-query result excerpt fed back into the loop
_RUNAI_CLUSTER_ID_CACHE: dict[tuple[str, str], str] = {}
_RUNAI_PROJECT_ID_CACHE: dict[tuple[str, str], str] = {}
_USER_PROMPT_CHARS = 6000
# An adapter-owned sentinel cannot be supplied by a JSON/MCP response.  It
# separates a collector-built observation envelope from arbitrary remote data
# that happens to contain `observation`, `polarity`, or `coverage` fields.
_VERIFIED_OBSERVATION = object()
_RECOVERY_URL_RE = re.compile(r"\b(?:https?|wss?)://\S+", re.IGNORECASE)
_RECOVERY_DIAGNOSTIC_RE = re.compile(
    r"\b(?:HTTP\s*(?:400|401|403|404|405|409|422|429|5\d\d)|bad\s+request|"
    r"forbidden|unauthori[sz]ed|permission|rbac|not\s+found|notfound|invalid|"
    r"syntax|parse|required|allowlist|unknown\s+(?:tool|kind|resource)|container|"
    r"timeout|timed\s+out|certificate|self[- ]signed|tls|ssl|connect(?:ion)?|"
    r"dns|name\s+resolution|datasource|service\s+account|token\s+unavailable)\b",
    re.IGNORECASE,
)
_LOGQL_UNSUPPORTED_SYNTAX_RE = re.compile(
    r"(?:\|\s*limit\b|\b(?:sort|order)\s+by\b|\b(?:select|from|where|group\s+by|having)\b)",
    re.IGNORECASE,
)
_PROMQL_UNSUPPORTED_SYNTAX_RE = re.compile(
    r"(?:\|\s*limit\b|\b(?:sort|order)\s+by\b|\b(?:select|from|where|having)\b)",
    re.IGNORECASE,
)
_QUERY_STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"')


async def run_drilldowns(
    settings: Settings,
    results: list[CollectorResult],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    *,
    blackboard: Any = None,
    query_memory: QueryMemory | None = None,
    evidence_sufficient: bool = False,
    deadline_monotonic: float | None = None,
    external_case_hints: list[dict[str, Any]] | None = None,
) -> None:
    """Run only the optional domain drill-downs still needed. Never raises."""
    if not settings.enable_agent_drilldown or not llm_configured(
        settings, settings.llm_model_drilldown
    ):
        return
    registry = _domain_tools(settings)
    # One receipt ledger is shared by every domain agent in this analysis.
    # Seed all collector results before tasks start so concurrently launched
    # agents cannot repeat a base query or a cross-domain adapter alias.
    memory = query_memory if query_memory is not None else QueryMemory()
    memory.seed_results(results, target)
    task_results = [
        (
            result,
            asyncio.create_task(
                _drill_one(
                    settings,
                    result,
                    registry[result.agent],
                    target,
                    plan.for_collector(result.agent) if plan else None,
                    blackboard=blackboard,
                    query_memory=memory,
                    skip_optional=evidence_sufficient,
                    deadline_monotonic=deadline_monotonic,
                    external_case_hints=_external_case_hints_for_domain(
                        result.agent, external_case_hints
                    ),
                )
            ),
        )
        for result in results
        # An unavailable first-pass collector is exactly where a bounded
        # domain agent can still add value: it may repair an over-broad or
        # malformed query, choose another read-only tool, or explain that the
        # failure is transport/configuration-wide.  Skipping it here used to
        # make a single base-query failure permanently disable that domain's
        # LLM even though its registry was configured.
        if result.agent in registry
    ]
    if not task_results:
        return
    tasks = {task: result for result, task in task_results}
    remaining = None if deadline_monotonic is None else deadline_monotonic - time.monotonic()
    done, pending = await asyncio.wait(
        tasks,
        timeout=None if remaining is None else max(0.0, remaining),
    )
    for task in pending:
        task.cancel()
    if pending:
        _log.info(
            "shared evidence budget reached; cancelled %d optional drill-down(s)",
            len(pending),
        )
        await asyncio.gather(*pending, return_exceptions=True)
    # Consume completed task exceptions: _drill_one is best-effort, but an
    # unexpected BaseException must not leak out of the coordinator.
    if done:
        await asyncio.gather(*done, return_exceptions=True)


async def _drill_one(
    settings: Settings,
    result: CollectorResult,
    tools: dict[str, dict[str, Any]],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    *,
    blackboard: Any = None,
    query_memory: QueryMemory | None = None,
    skip_optional: bool = False,
    deadline_monotonic: float | None = None,
    external_case_hints: list[dict[str, Any]] | None = None,
) -> None:
    """One agent's adaptive think->query->observe loop over its own evidence."""
    masker = _drilldown_masker(settings)
    try:
        if _system_node_scope_unavailable(result, target):
            return
        architecture = _implicated_architecture(settings, result, target)
        history: list[dict[str, Any]] = []
        # Keep the legacy local fingerprint for standalone callers, but use the
        # run-scoped ledger for actual execution. It spans every evidence
        # domain, not just Kubernetes.
        seen_queries: set[str] = _existing_query_fingerprints(result, target)
        memory = query_memory if query_memory is not None else QueryMemory()
        memory.seed_result(result, target)
        probe_attempts: dict[str, int] = {}
        system_no_node_query_attempted = False
        # A TypeDB/YAML probe is executable only through this agent's existing
        # read-only registry.  Run it before asking the LLM to improvise a
        # query: the declarative probe is the durable operational knowledge,
        # while the LLM decides what additional discriminator is worthwhile.
        for query in _declared_probe_queries(plan, tools, target):
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                return
            if (
                result.agent == "system"
                and not target.node
                and str(query.get("tool") or "") == "system_log_query"
            ):
                if system_no_node_query_attempted:
                    continue
                system_no_node_query_attempted = True
            key = _query_fingerprint(query, target)
            if key in seen_queries:
                continue
            execution_key = domain_query_key(result.agent, query, target)
            if not memory.claim(execution_key):
                continue
            seen_queries.add(key)
            await _run_query(
                settings,
                result,
                tools,
                target,
                plan,
                query,
                history,
                masker,
                blackboard=blackboard,
                query_memory=memory,
                execution_key=execution_key,
                artifact_type="ontology_probe",
                probe_attempts=probe_attempts,
            )
        assessments = result.details.get("ontology_probe_assessments", [])
        declared_probes_settled = not assessments or all(
            isinstance(item, dict) and item.get("verdict") == "supports"
            for item in assessments
        )
        if skip_optional and declared_probes_settled:
            _log.info(
                "drilldown %s: required probes complete; optional rounds skipped",
                result.agent,
            )
            return
        step = 0
        invalid_query_repair_used = False
        parser_repair_pending = False
        parser_repair_used = False
        decision_round_limit = settings.max_investigation_steps or 3
        while step < decision_round_limit:
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                _log.info(
                    "shared evidence budget reached; stopped optional %s drill-down",
                    result.agent,
                )
                break
            step += 1
            user_prompt = masker.mask_text(
                _user_prompt(
                    result,
                    target,
                    plan,
                    history,
                    architecture,
                    blackboard=blackboard,
                    external_case_hints=external_case_hints,
                )
            )
            decision_system = _system_prompt(result.agent, tools)
            decision = await complete_json(
                settings,
                system=decision_system,
                user=user_prompt,
                model=settings.llm_model_drilldown,
            )
            if decision is None:
                # An LLM transport/parse failure must be distinguishable from a
                # legitimate "done" — otherwise a dead LLM looks like a satisfied
                # agent and nobody notices drill-down never ran. Re-ask once via
                # complete_with_error to surface the REASON, so a persistent config
                # error (HTTP 400 — the litellm-provider incident) or an empty body
                # is distinguishable from a transient blip that recovered.
                _text, decision_error = await complete_with_error(
                    settings,
                    system=decision_system,
                    user=user_prompt,
                    model=settings.llm_model_drilldown,
                )
                detail = f": {decision_error}" if decision_error else ""
                result.warnings.append(
                    f"{result.agent} drill-down stopped at step {step}: LLM decision call failed{detail}"
                )
                break
            if not isinstance(decision, dict) or decision.get("action") != "query":
                _log.info(
                    "drilldown %s: done after %d follow-up quer(ies)",
                    result.agent,
                    len(history),
                )
                break
            is_parser_repair = parser_repair_pending
            if is_parser_repair:
                parser_repair_pending = False
                parser_repair_used = True
            queries: list[tuple[dict[str, Any], str]] = []
            rejected: list[dict[str, Any]] = []
            for q in decision.get("queries") or []:
                if not isinstance(q, dict):
                    rejected.append(_rejected_query_feedback(q, tools))
                    continue
                if str(q.get("tool") or "") not in tools:
                    rejected.append(_rejected_query_feedback(q, tools))
                    continue
                if not _valid_domain_query(q):
                    # Do not turn a PromQL/LogQL name hallucinated as a
                    # Kubernetes kind into an unavailable evidence card. The
                    # tool descriptions already name the valid kinds; keeping
                    # this out of the history also prevents repeated noise.
                    rejected.append(_rejected_query_feedback(q, tools))
                    continue
                if (
                    result.agent == "system"
                    and not target.node
                    and str(q.get("tool") or "") == "system_log_query"
                ):
                    if system_no_node_query_attempted:
                        continue
                    system_no_node_query_attempted = True
                key = _query_fingerprint(q, target)
                if key in seen_queries:
                    continue
                execution_key = domain_query_key(result.agent, q, target)
                if not memory.claim(execution_key):
                    continue
                seen_queries.add(key)
                queries.append((q, execution_key))
            if rejected:
                history.extend(rejected)
            if not queries:
                # Give one malformed/unknown-tool decision a correction round.
                # This remains bounded by both this one-shot allowance and the
                # normal reasoning-round/deadline limits.  Duplicate valid
                # queries still stop immediately instead of looping.
                if (
                    rejected
                    and not invalid_query_repair_used
                    and step < decision_round_limit
                ):
                    invalid_query_repair_used = True
                    continue
                result.warnings.append(
                    f"{result.agent} drill-down stopped at step {step}: "
                    "no new allowed read-only query was returned"
                )
                break
            _log.info(
                "drilldown %s: step %d running %d quer(ies)",
                result.agent,
                step + 1,
                len(queries),
            )
            # The model batches independent read-only discriminators in one
            # reasoning round. Run that batch concurrently: the round limit is
            # deliberately small (three), while evidence breadth is not.
            parser_rejections = await asyncio.gather(
                *(
                    _run_query(
                        settings,
                        result,
                        tools,
                        target,
                        plan,
                        q,
                        history,
                        masker,
                        blackboard=blackboard,
                        query_memory=memory,
                        execution_key=execution_key,
                    )
                    for q, execution_key in queries
                )
            )
            if any(parser_rejections):
                if is_parser_repair:
                    result.warnings.append(
                        f"{result.agent} drill-down stopped after one query-syntax repair attempt"
                    )
                    break
                if not parser_repair_used:
                    # The next LLM turn receives the structured HTTP 400/parse
                    # feedback in history. One repair is enough; repeated parser
                    # failures must not consume the drill-down budget.
                    parser_repair_pending = True
            if _system_node_scope_unavailable(result, target):
                break
    except Exception as exc:  # noqa: BLE001 - drill-down is best-effort; base evidence stands
        result.warnings.append(
            f"{result.agent} drill-down aborted: "
            f"{masker.mask_text(f'{exc.__class__.__name__}: {exc}')}"
        )
        _log.debug("drill-down for %s aborted", result.agent, exc_info=True)


async def _call_tool_safely(
    call: Any, settings: Settings, target: AnalysisTarget, args: dict
) -> dict:
    try:
        outcome = await call(settings, target, args)
        return outcome if isinstance(outcome, dict) else {"error": "tool returned no result"}
    except Exception as exc:  # noqa: BLE001 - a failing query is an observation
        return {"error": f"{exc.__class__.__name__}: {exc}"}


def _rejected_query_feedback(value: object, tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Machine-readable repair hint for a model-generated query we did not run.

    This object is prompt-only operational feedback.  It never becomes an
    artifact or a blackboard fact, so a hallucinated kind cannot become RCA
    evidence merely by appearing in a rejected request.
    """
    query = value if isinstance(value, dict) else {}
    tool = str(query.get("tool") or "")[:80]
    args = query.get("args") if isinstance(query.get("args"), dict) else {}
    requested_kind = str(args.get("kind") or "")[:80]
    reason = "query must be a JSON object"
    if isinstance(value, dict) and tool not in tools:
        reason = "tool is not available in this evidence domain"
    elif tool == "k8s_read" and resolve_read_kind(requested_kind) is None:
        reason = "kind is not an allowlisted Kubernetes resource"
    elif isinstance(value, dict):
        reason = "arguments are malformed or outside the read-only contract"
    feedback: dict[str, Any] = {
        "status": "rejected",
        "reason": reason,
        "allowed_tools": sorted(tools),
        "instruction": (
            "Operational feedback only, not incident evidence. Correct the tool/arguments "
            "and return a new narrow read-only query."
        ),
    }
    if tool:
        feedback["requested_tool"] = tool
    if requested_kind:
        feedback["requested_kind"] = requested_kind
    if tool == "k8s_read":
        feedback["allowed_kinds"] = sorted(_READ_KINDS)
    return feedback


def _query_failure_feedback(outcome: dict[str, Any], error: object) -> dict[str, Any]:
    """Expose just enough failed-call detail for the next LLM round to recover.

    Failed response bodies remain excluded: they can contain stale incident
    keywords and are not evidence.  Adapter-owned status/error-code metadata and
    recognized operational diagnostics are safe to use as query-repair input.
    """
    raw = " ".join(str(error or "query failed").split())
    fallback_detail = str(outcome.get("mcp_fallback") or "")
    if fallback_detail:
        raw = f"{raw} {fallback_detail}"
    nested = outcome.get("result") if isinstance(outcome.get("result"), dict) else {}
    metadata = {
        key: outcome.get(key) if outcome.get(key) not in (None, "") else nested.get(key)
        for key in ("error_code", "status_code", "transport_error", "retryable")
    }
    if metadata.get("status_code") in (None, ""):
        status_match = re.search(r"\bHTTP\s*(\d{3})\b", raw, re.IGNORECASE)
        if status_match:
            metadata["status_code"] = int(status_match.group(1))
    # Full websocket/HTTP request URLs add noise and may carry query parameters.
    scrubbed = _RECOVERY_URL_RE.sub("[endpoint]", raw)[:500]
    recognized = bool(_RECOVERY_DIAGNOSTIC_RE.search(scrubbed))
    category = _query_failure_category(metadata, scrubbed if recognized else "query failed")
    diagnostic = _safe_recovery_diagnostic(scrubbed, category) if recognized else "query failed"
    retryable = metadata.get("retryable")
    if category == "authorization":
        guidance = "Do not retry the same call; use another allowed read-only tool if possible."
    elif category == "target_not_found":
        guidance = (
            "Discover the current target identity, then retry with that exact name and scope."
        )
    elif category in {"invalid_request", "container_selection"}:
        guidance = "Correct the query syntax/arguments or container selection before retrying."
    elif retryable is False:
        guidance = "Do not repeat this call unchanged; choose another allowed discriminator."
    else:
        guidance = "Change the scope/query/tool or make at most one justified retry."
    feedback: dict[str, Any] = {
        "status": "failed",
        "error_category": category,
        "diagnostic": diagnostic,
        "instruction": f"Operational feedback only, not incident evidence. {guidance}",
    }
    for key in ("error_code", "status_code", "transport_error", "retryable"):
        value = metadata.get(key)
        if value not in (None, ""):
            feedback[key] = value
    if category == "invalid_request" and "parse error" in scrubbed.casefold():
        feedback["parser_error"] = "query parser rejected the supplied syntax"
    return feedback


def _safe_recovery_diagnostic(raw: str, category: str) -> str:
    """Canonicalize an error without replaying an arbitrary failed response body."""
    status_match = re.search(r"\bHTTP\s*(\d{3})\b", raw, re.IGNORECASE)
    prefix = f"HTTP {status_match.group(1)}: " if status_match else ""
    lowered = raw.lower()
    if category == "authorization":
        detail = "authorization/RBAC denied the read-only query"
    elif category == "target_not_found":
        detail = "the requested target was not found"
    elif category == "container_selection":
        detail = "container selection is missing or invalid"
    elif category == "configuration":
        if "datasource" in lowered:
            detail = "Grafana datasource UID is missing, invalid, or inaccessible"
        elif "token" in lowered or "service account" in lowered:
            detail = "service-account credential is unavailable"
        else:
            detail = "collector configuration is unavailable or invalid"
    elif category == "invalid_request":
        detail = "query syntax or arguments are invalid"
    elif category == "rate_limited":
        detail = "backend rate limit reached"
    elif category == "transport":
        if "certificate" in lowered or "self-signed" in lowered or "tls" in lowered:
            detail = "TLS certificate validation failed"
        elif "timeout" in lowered or "timed out" in lowered:
            detail = "transport timed out"
        else:
            detail = "transport connection failed"
    elif category == "backend_failure":
        detail = "backend returned a server error"
    else:
        detail = "query execution failed"
    return f"{prefix}{detail}"[:300]


def _query_failure_category(outcome: dict[str, Any], diagnostic: str) -> str:
    code = str(outcome.get("error_code") or "").lower()
    lowered = diagnostic.lower()
    status = outcome.get("status_code")
    if status in {401, 403} or any(
        marker in f"{code} {lowered}"
        for marker in ("forbidden", "unauthorized", "permission", "rbac")
    ):
        return "authorization"
    if status == 404 or "not found" in lowered or "notfound" in lowered:
        return "target_not_found"
    if "container" in lowered:
        return "container_selection"
    if "datasource" in lowered or "service account" in lowered or "token unavailable" in lowered:
        return "configuration"
    if status in {400, 405, 409, 422} or any(
        marker in lowered
        for marker in ("bad request", "invalid", "syntax", "parse", "required", "allowlist")
    ):
        return "invalid_request"
    if status == 429:
        return "rate_limited"
    if outcome.get("transport_error") or any(
        marker in lowered
        for marker in ("timeout", "timed out", "certificate", "self-signed", "tls", "ssl", "dns")
    ):
        return "transport"
    if isinstance(status, int) and status >= 500:
        return "backend_failure"
    return "execution"


async def _run_query(
    settings: Settings,
    result: CollectorResult,
    tools: dict[str, dict[str, Any]],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    query: dict[str, Any],
    history: list[dict[str, Any]],
    masker: Any,
    *,
    blackboard: Any = None,
    query_memory: QueryMemory | None = None,
    execution_key: str = "",
    artifact_type: str = "drilldown_query",
    probe_attempts: dict[str, int] | None = None,
) -> bool:
    """Execute one registry-validated query and preserve its observation."""
    name = str(query.get("tool") or "")
    if name not in tools or not _valid_domain_query(query):
        return False
    args = query.get("args") if isinstance(query.get("args"), dict) else {}
    raw_outcome = await _call_tool_safely(tools[name]["call"], settings, target, args)
    if query_memory is not None and execution_key:
        query_memory.complete(
            execution_key,
            succeeded=not bool(raw_outcome.get("error")),
        )
    raw_result = raw_outcome.get("result") if isinstance(raw_outcome, dict) else None
    raw_markers = _drilldown_salient_markers(
        result.agent,
        name,
        raw_outcome,
        raw_result,
    )
    outcome = masker.mask_object(raw_outcome)
    if not isinstance(outcome, dict):
        outcome = {"error": "tool returned no result"}
    error = outcome.get("error")
    artifact_result = _typed_artifact_result(
        outcome, error=error, tool=name, artifact_type=artifact_type
    )
    probe = query.get("_ontology_probe")
    execution: dict[str, Any] = {}
    if artifact_type == "ontology_probe" and isinstance(probe, dict):
        # Evaluate against the final artifact envelope, not the raw tool
        # response. A remote payload can repeat a signal token (and even
        # top-level polarity/coverage fields) without being scoped evidence.
        assessment_outcome = {
            "status": "unavailable" if error else "ok",
            "error": error,
            "result": artifact_result,
            "observation": artifact_result.get("observation"),
        }
        assessment = evaluate_probe(
            probe, assessment_outcome, require_scoped_observation=True
        ).as_dict()
        template_id = _template_id(probe)
        attempts = probe_attempts if probe_attempts is not None else {}
        attempt_index = attempts.get(template_id, 0) + 1
        attempts[template_id] = attempt_index
        directive = plan.diagnostic_directive if plan else {}
        run_id = str(directive.get("run_id") or "").strip() if isinstance(directive, dict) else ""
        execution = {
            "template_id": template_id,
            "attempt_index": attempt_index,
            "executed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        if run_id and template_id:
            execution["execution_id"] = f"{run_id}:{template_id}:{attempt_index}"
            execution["hypothesis_ids"] = [
                str(value) for value in probe.get("hypothesis_ids") or [] if str(value).strip()
            ]
        assessment.update(execution)
        assessments = result.details.setdefault("ontology_probe_assessments", [])
        if isinstance(assessments, list):
            assessments.append(assessment)
    history_outcome = _query_failure_feedback(outcome, error) if error else outcome
    history.append(
        {
            "tool": name,
            "args": json.dumps(args, default=str)[:300],
            "outcome": json.dumps(history_outcome, default=str)[:_RESULT_CHARS],
        }
    )
    # Transport notes surface as collector warnings (Diagnostics panel), never
    # inside evidence summaries which feed the ranker/signature matchers.
    note = str(outcome.get("mcp_fallback") or "")
    if note and note not in result.warnings:
        result.warnings.append(note)
    markers = [] if error else [masker.mask_text(str(marker)) for marker in raw_markers]
    summary = str(outcome.get("summary") or error or name)
    if markers:
        summary = f"{summary} — {signals_line(markers, getattr(settings, 'language', 'en'))}"
    # A query the agent wrote itself that came back malformed (400 / parse /
    # syntax) is not a finding — mark it no-evidence so the trail hides it,
    # exactly like a failed exec probe. Real failures (auth, 404, timeout,
    # backend 5xx) keep their error summary and stay visible.
    if error and _query_failure_category(outcome, str(error)) == "invalid_request":
        summary = f"{NO_EVIDENCE} " + ko_en(
            settings,
            "질의 구문이 잘못되어 실행되지 않았습니다.",
            "The query was malformed and did not run.",
        )
    result.artifacts.append(
        artifact(
            agent=result.agent,
            source=result.agent,
            type=artifact_type,
            status="unavailable" if error else "ok",
            confidence="medium",
            query=str(outcome.get("query") or name),
            title=outcome.get("title"),
            highlights=markers or None,
            summary=summary,
            result=artifact_result,
        )
    )
    if artifact_type == "ontology_probe" and isinstance(probe, dict):
        assessments = result.details.get("ontology_probe_assessments")
        if isinstance(assessments, list) and assessments:
            stored_artifact = result.artifacts[-1]
            assessments[-1]["artifact_index"] = len(result.artifacts) - 1
            if evidence_id := str(getattr(stored_artifact, "evidence_id", "") or ""):
                assessments[-1]["evidence_ids"] = [evidence_id]
    _record_blackboard(blackboard, result, target)
    return bool(
        error
        and name in {"logql_query", "promql_query"}
        and _query_failure_category(outcome, str(error)) == "invalid_request"
    )


def _drilldown_salient_markers(
    agent: str,
    tool: str,
    outcome: object,
    raw_result: object,
) -> list[str]:
    """Extract highlights only from returned observations, never query intent.

    Grafana MCP result envelopes echo LogQL/PromQL and may include debug hints
    such as ``possibleCauses`` even when no row/series matched. Scanning the
    whole envelope therefore turns words we asked for into words we observed.
    Unverified generic tools stay context-only; verified adapters may expose
    highlights only for an explicit positive observation.
    """
    if not isinstance(outcome, dict) or outcome.get("error"):
        return []
    if agent == "kubernetes":
        return kubernetes_salient_markers(raw_result)
    if agent == "loki" and tool == "logql_query":
        return salient_markers(_loki_returned_failure_lines(raw_result))
    if outcome.get("_verified_observation") is not _VERIFIED_OBSERVATION:
        return []
    observation = outcome.get("observation")
    if not isinstance(observation, dict) or observation.get("polarity") != "present":
        return []
    return salient_markers(raw_result)


def _loki_returned_failure_lines(value: object) -> list[str]:
    if not isinstance(value, dict) or int(value.get("line_count") or 0) <= 0:
        return []
    lines: list[str] = []
    entries = value.get("sample_entries")
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("line"), str):
            lines.append(str(entry["line"]))
    if not lines:
        candidates = value.get("sample_lines") or value.get("lines")
        if isinstance(candidates, list):
            lines.extend(str(line) for line in candidates)
    return [line for line in lines if _loki_line_affirms_failure(line)]


def _typed_artifact_result(
    outcome: dict[str, Any], *, error: object, tool: str, artifact_type: str
) -> dict[str, Any]:
    """Keep a drilldown tool's verdict attached to its displayed result.

    Tool adapters sometimes put ``polarity``/``coverage`` beside ``result``.
    Dropping that envelope makes a partial current-state observation look like
    an unstructured successful artifact, which legacy ranking treats as proof.
    Unknown is the safe default for adapters that have not yet declared a
    bounded observation contract.
    """
    raw_result = outcome.get("result")
    payload = dict(raw_result) if isinstance(raw_result, dict) else {"data": raw_result}
    # A response body is untrusted data, even when its HTTP request succeeded.
    # In particular, a Run:ai/Kubernetes API object is free to contain a field
    # named ``observation``; treating that field as our evidence envelope would
    # let a remote response assert ``present/scoped`` without proving the
    # requested entity, value, or incident window. Only an adapter can opt in
    # to a typed verdict it constructed and validated itself.
    verified_observation = outcome.get("_verified_observation") is _VERIFIED_OBSERVATION
    top_level_observation = outcome.get("observation")
    observation = (
        dict(top_level_observation)
        if verified_observation and isinstance(top_level_observation, dict)
        else {}
    )
    polarity = str(observation.get("polarity") or outcome.get("polarity") or "").lower()
    coverage = str(observation.get("coverage") or outcome.get("coverage") or "").lower()
    if polarity not in {"present", "absent", "unknown", "unavailable"}:
        polarity = "unavailable" if error else "unknown"
    if coverage not in {"scoped", "partial", "unknown"}:
        coverage = "unknown" if polarity == "unavailable" else "partial"
    # The convenience top-level ``polarity``/``coverage`` fields remain useful
    # for partial operational context, but must not by themselves promote a
    # successful transport into causal support. Scoped positive/negative
    # semantics are reserved for a tool adapter that set the marker above.
    if not verified_observation and polarity in {"present", "absent"} and coverage == "scoped":
        polarity, coverage = "unknown", "partial"
    observation = {
        **observation,
        "kind": str(observation.get("kind") or artifact_type),
        "predicate": str(observation.get("predicate") or outcome.get("predicate") or tool),
        "polarity": polarity,
        "coverage": coverage,
    }
    if "observation_window" not in observation and isinstance(
        outcome.get("observation_window"), dict
    ):
        observation["observation_window"] = outcome["observation_window"]
    payload["observation"] = observation
    return payload


_PROBE_PLACEHOLDER = re.compile(r"{{([a-zA-Z_][a-zA-Z0-9_]*)}}")


def _probe_target_values(target: AnalysisTarget) -> dict[str, str]:
    """The complete, deliberately small placeholder vocabulary for probes.

    Values come only from the resolved alert target.  Do not add evidence text,
    LLM output, or an empty fallback here: a missing identifier must skip the
    targeted probe rather than widening it into a namespace/cluster sweep.
    """
    names = (
        "namespace",
        "pod",
        "node",
        "workload",
        "workload_name",
        "project",
        "service",
        "component",
        "storage_claim",
        "volume",
    )
    aliases = {"workload": "workload_name"}
    values: dict[str, str] = {}
    for name in names:
        value = str(getattr(target, aliases.get(name, name), "") or "").strip()
        # Alert metadata is untrusted.  Reject query-breaking control characters
        # and nested template syntax; _resolve_probe_template then treats this
        # exactly like an unresolved value and skips the probe safely.
        if (
            "{{" in value
            or "}}" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            value = ""
        values[name] = value
    return values


def _declared_probe_queries(
    plan: InvestigationPlan | None,
    tools: dict[str, dict[str, Any]],
    target: AnalysisTarget,
) -> list[dict[str, Any]]:
    """Resolve only curated probe templates that this agent can safely execute.

    Unknown or empty placeholders cause the whole probe to be skipped.  That is
    intentional: falling back to an empty namespace/name could turn a targeted
    diagnostic into a cluster-wide sweep.
    """
    directive = plan.diagnostic_directive if plan else {}
    raw_probes = directive.get("probes") if isinstance(directive, dict) else []
    if not isinstance(raw_probes, list):
        return []
    values = _probe_target_values(target)
    queries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_probe in raw_probes:
        if not isinstance(raw_probe, dict):
            continue
        tool = str(raw_probe.get("tool") or "")
        template = raw_probe.get("arguments_template")
        if tool not in tools or not isinstance(template, dict):
            continue
        args = _resolve_probe_template(template, values)
        if args is None:
            continue
        probe = dict(raw_probe)
        probe["template_id"] = _template_id(probe)
        query = {"tool": tool, "args": args, "_ontology_probe": probe}
        fingerprint = f"{probe['template_id']}:{_query_fingerprint(query, target)}"
        if fingerprint not in seen:
            seen.add(fingerprint)
            queries.append(query)
    return queries


def _template_id(probe: dict[str, Any]) -> str:
    authored = str(
        probe.get("template_id") or probe.get("id") or probe.get("probe_id") or ""
    ).strip()
    if authored:
        return authored
    canonical = json.dumps(
        {
            "tool": str(probe.get("tool") or ""),
            "arguments_template": probe.get("arguments_template") or {},
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return f"legacy-probe-{sha256(canonical).hexdigest()[:12]}"


def _query_fingerprint(
    query: dict[str, Any], target: AnalysisTarget | None = None
) -> str:
    """Deduplicate execution identity, including Kubernetes tool aliases."""
    tool = str(query.get("tool") or "")
    args = query.get("args") if isinstance(query.get("args"), dict) else {}
    if tool in {"k8s_read", "k8s_describe"}:
        kind = resolve_read_kind(str(args.get("kind") or "")) or str(args.get("kind") or "")
        # k8s_describe defaults to the alert namespace in its adapter;
        # k8s_read does not. Preserve that execution distinction so an omitted
        # namespace (cluster-wide list) is never deduped against a scoped read.
        namespace = str(args.get("namespace") or "")
        if tool == "k8s_describe" and not namespace and target is not None:
            namespace = target.namespace
        name = str(args.get("name") or "")
        # A named Pod k8s_read is promoted to the same YAML + describe/events
        # operation as k8s_describe, so those two model choices are one read.
        operation = "describe" if kind == "pods" and name else tool
        return json.dumps(
            {
                "operation": operation,
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "label_selector": str(args.get("label_selector") or ""),
            },
            sort_keys=True,
        )
    return json.dumps(
        {key: value for key, value in query.items() if not str(key).startswith("_")},
        sort_keys=True,
        default=str,
    )


def _existing_query_fingerprints(
    result: CollectorResult, target: AnalysisTarget
) -> set[str]:
    """Translate typed Kubernetes artifacts into drill-down execution IDs."""
    if result.agent != "kubernetes":
        return set()
    seen: set[str] = set()
    for item in result.artifacts:
        status = str(getattr(item, "status", "") or "")
        if status != "ok":
            continue
        artifact_type = str(getattr(item, "type", "") or "")
        query: dict[str, Any] | None = None
        if artifact_type == "kubernetes_warning_events" and target.namespace:
            query = {
                "tool": "k8s_read",
                "args": {"kind": "events", "namespace": target.namespace},
            }
        elif artifact_type == "kubernetes_node_condition" and target.node:
            query = {
                "tool": "k8s_read",
                "args": {"kind": "nodes", "name": target.node},
            }
        elif artifact_type == "pod_inspection" and target.pod:
            query = {
                "tool": "k8s_describe",
                "args": {
                    "kind": "pods",
                    "namespace": target.namespace,
                    "name": target.pod,
                },
            }
        elif artifact_type in {
            "adhoc_query",
            "followup_query",
            "ontology_probe",
            "drilldown_query",
        }:
            payload = getattr(item, "result", None)
            if isinstance(payload, dict) and payload.get("kind"):
                query = {
                    "tool": (
                        "k8s_describe"
                        if str(payload.get("operation") or "") == "describe"
                        else "k8s_read"
                    ),
                    "args": {
                        "kind": payload.get("kind"),
                        "namespace": payload.get("namespace") or "",
                        "name": payload.get("name") or "",
                        "label_selector": payload.get("label_selector") or "",
                    },
                }
        if query is not None:
            seen.add(_query_fingerprint(query, target))
    return seen


def _system_node_scope_unavailable(result: CollectorResult, target: AnalysisTarget) -> bool:
    if result.agent != "system" or target.node:
        return False
    return any(
        getattr(item, "type", "") in {"drilldown_query", "ontology_probe"}
        and "the alert has no node scope" in str(getattr(item, "summary", ""))
        for item in result.artifacts
    )


def _valid_domain_query(query: dict[str, Any]) -> bool:
    """Reject malformed per-domain arguments before invoking a transport."""
    tool = str(query.get("tool") or "")
    if tool == "k8s_read":
        args = query.get("args")
        return isinstance(args, dict) and resolve_read_kind(str(args.get("kind") or "")) is not None
    if tool not in {"logql_query", "promql_query"}:
        return True
    args = query.get("args")
    if not isinstance(args, dict):
        return False
    _query, error = _sanitize_metric_query(str(args.get("query") or ""), tool)
    return error is None


def _sanitize_metric_query(query: str, tool: str) -> tuple[str, str | None]:
    """Normalize JSON-double-escaped quotes and reject non-query-language syntax."""
    normalized = " ".join(query.strip().split())
    # Some model responses serialize the query string twice, leaving literal
    # backslash-quotes for Loki/Prometheus to parse as invalid escapes.
    normalized = normalized.replace(r'\"', '"')
    unsupported = (
        _LOGQL_UNSUPPORTED_SYNTAX_RE
        if tool == "logql_query"
        else _PROMQL_UNSUPPORTED_SYNTAX_RE
    )
    # Do not reject a perfectly valid regex/line filter merely because its
    # literal text happens to contain words such as "select" or "sort by".
    syntax_view = _QUERY_STRING_LITERAL_RE.sub('""', normalized)
    if unsupported.search(syntax_view):
        language = "LogQL" if tool == "logql_query" else "PromQL"
        return "", f"invalid {language} query: unsupported sort/limit or SQL syntax"
    return normalized, None


def _resolve_probe_template(value: Any, values: dict[str, str]) -> Any | None:
    if isinstance(value, dict):
        resolved = {str(key): _resolve_probe_template(item, values) for key, item in value.items()}
        return None if any(item is None for item in resolved.values()) else resolved
    if isinstance(value, list):
        resolved = [_resolve_probe_template(item, values) for item in value]
        return None if any(item is None for item in resolved) else resolved
    if not isinstance(value, str):
        return value

    unresolved = False

    def replace(match: re.Match[str]) -> str:
        nonlocal unresolved
        replacement = values.get(match.group(1), "")
        if not replacement:
            unresolved = True
        return replacement

    resolved = _PROBE_PLACEHOLDER.sub(replace, value)
    return None if unresolved else resolved


def _drilldown_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


# ---------------------------------------------------------------------------
# Prompts


# Per-domain "what to actively hunt for" hints. These nudge each agent to use its
# knowledge of common Run:ai / GPU / Kubernetes failure modes INSIDE its own
# territory, so it keeps digging for the real fault instead of accepting the base
# collector's shallow first pass.
_DOMAIN_FOCUS = {
    "kubernetes": (
        "pod phase and container waiting/terminated reasons, restart counts and "
        "last-state exit codes, OOMKilled / CrashLoopBackOff / ImagePullBackOff / "
        "FailedScheduling / FailedMount / Evicted events, the owning controller "
        "(Job / Deployment / RunaiJob / ReplicaSet), and node conditions, "
        "pressure and taints for the assigned node"
    ),
    "prometheus": (
        "restart and OOM counters, pending and unschedulable pods, GPU / CPU / "
        "memory saturation, resource-quota vs allocation for the project/queue, "
        "and metric TRENDS across the incident window — not just the instant value"
    ),
    "loki": (
        "crash / panic / fatal stack traces, GPU Xid / NVRM / NCCL lines, and "
        "scheduler / admission / quota / reconcile errors that NAME this workload; "
        "find the FIRST error line in the incident window (the origin, not the "
        "repeated downstream symptom)"
    ),
    "runai": (
        "workload phase and status history, project and queue quota vs allocation, "
        "the scheduling / preemption reason, and the workload's controller and pod "
        "identity"
    ),
    "postgres": (
        "the control-plane rows for THIS workload / project / queue — status, "
        "quota, scheduling decisions, and audit / authorization entries around the "
        "incident time"
    ),
    "system": (
        "node-scoped kernel, NVIDIA driver, NVLink, hardware, filesystem and OOM "
        "signals; use historical journal scope for a past incident and treat live "
        "dmesg/syslog tails only as current context"
    ),
    "change": (
        "the first target-scoped controller, Pod, node-condition, Event or Helm "
        "metadata change inside the incident window that could precede the symptom"
    ),
}


def _system_prompt(agent: str, tools: dict[str, dict[str, Any]]) -> str:
    tool_lines = "\n".join(f"- {name}: {spec['description']}" for name, spec in tools.items())
    focus = _DOMAIN_FOCUS.get(
        agent, "the evidence most relevant to the incident within your domain"
    )
    return (
        f"You are the {agent} evidence agent for a Run:ai GPU-platform RCA, autonomously "
        "and AGGRESSIVELY investigating YOUR domain only. Do not settle for the base "
        "collector's first pass: use your expert knowledge of common Run:ai / GPU / "
        "Kubernetes failure modes to actively hunt down the fault inside your own "
        "territory.\n"
        f"For your domain, dig into: {focus}.\n"
        "How to work:\n"
        "- Form a concrete hypothesis from the evidence so far, then run READ-ONLY "
        "follow-up queries that would confirm or refute it. When a lead is ambiguous, "
        "re-query with a NARROWER scope (one pod, one namespace, one metric series, a "
        "tighter time filter or regex) to pin it down.\n"
        "- A condition name or metric label alone is not a failure. Verify its status and "
        "sample value; False or zero is refuting evidence, not a positive signal.\n"
        "- Kubernetes spec/configuration expresses intent, not an observed failure. In "
        "particular, spec.preemptionPolicy=PreemptLowerPriority does NOT prove that "
        "preemption happened; require an active condition or target-scoped Warning Event.\n"
        "- For a named alert pod, inspect full Pod YAML and describe-level status/events before "
        "broad namespace/project reads. If a container is waiting, terminated, or restarted, "
        "inspect that container's logs (including the prior instance when available).\n"
        "- Fetch data RELATED to the incident — the workload's controller, its "
        "project/queue, the Run:ai control-plane component involved, correlated "
        "namespaces and time windows — never your own datasource's health (the base "
        "collector already covered that).\n"
        "- KEEP GOING while a plausible in-domain cause is still untested, your key "
        "evidence is thin or ambiguous, or you have not yet found the ORIGIN (not just "
        "a downstream symptom). Do NOT stop at the first plausible-looking line. Answer "
        "action=done ONLY when your own domain is thoroughly covered and further queries "
        "would be redundant.\n"
        "- drilldown_so_far entries with status=failed/rejected and "
        "base_collection.execution_diagnostics are OPERATIONAL FEEDBACK, never incident "
        "evidence. Use them to repair a malformed selector/argument, discover the correct "
        "target/container, or switch to another allowed read-only tool. Do not blindly repeat "
        "an authorization/configuration-wide failure, and do not stop while a safe alternative "
        "discriminator remains.\n"
        "- If ontology_guidance is supplied, turn its questions and checks into narrow "
        "queries using only your tools. Its candidate family is a hypothesis, not evidence: "
        "actively look for the listed disconfirmations too. Respect its avoid guidance and use "
        "its interpretation notes to classify ambiguous results. Never execute check prose as a "
        "command. If it includes structured probes, use only probes whose tool is in your "
        "registry and resolve their placeholders from the incident scope. External-case "
        "investigation leads are also unverified hypotheses, not evidence or fixes; use them "
        "only to choose a narrow query available in your registry.\n"
        "- Stay strictly read-only and inside your tools, and avoid blind sweeps — every "
        "query must test a specific idea. Batch all independent checks you can run now "
        "into the same queries array; query count is not the scarce resource, reasoning "
        "rounds are.\n"
        "- LogQL has NO sort/limit pipeline stages: use only line filters (`|=` / `|~`) "
        "after the selector; ordering and limit are transport parameters, not query syntax.\n"
        f"Tools available to you (your only tools; there are no others):\n{tool_lines}\n"
        'Respond with ONLY JSON: {"action":"query"|"done","reason":str,'
        '"queries":[{"tool":str,"args":{...}}]}.'
    )


def _user_prompt(
    result: CollectorResult,
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    history: list[dict[str, Any]],
    architecture: list[str] | None = None,
    *,
    blackboard: Any = None,
    external_case_hints: list[dict[str, Any]] | None = None,
) -> str:
    plan_dict = plan.as_dict() if plan else {}
    stable = {
        "target": {
            key: getattr(target, key, "")
            for key in (
                "namespace",
                "workload_name",
                "pod",
                "node",
                "project",
                "service",
                "component",
                "storage_claim",
                "volume",
            )
        },
        "plan_focus": plan_dict.get("focus"),
        "hypotheses": (plan_dict.get("hypotheses") or [])[:4],
        "historical_case_cards": (plan_dict.get("case_cards") or [])[:3],
        "ontology_guidance": _ontology_guidance(plan, external_case_hints=external_case_hints),
    }
    if architecture:
        # Curated platform topology for the components THIS incident implicates:
        # what each does when broken and which dependency to check next — the
        # "thinking material" that used to reach only the playbook renderer.
        stable["platform_architecture"] = architecture
    variable = {
        "my_summary": (
            (result.summary or "")[:1200]
            if result.status in {"ok", "partial"}
            else "Base collection unavailable; use base_collection operational feedback."
        ),
        "base_collection": _base_collection_feedback(result),
        "my_artifacts": [
            _artifact_prompt_item(art)
            for art in result.artifacts[-8:]
            if _artifact_is_evidence(art)
        ],
        "drilldown_so_far": history[-8:],
        "shared_observations": _blackboard_prompt_view(blackboard, target),
    }
    return _capped_json_prompt(
        stable,
        variable,
        max_chars=_USER_PROMPT_CHARS,
        trim_keys=("drilldown_so_far", "my_artifacts", "shared_observations"),
    )


def _base_collection_feedback(result: CollectorResult) -> dict[str, Any]:
    """Prompt-only status explaining why the first pass had no usable data."""
    feedback: dict[str, Any] = {
        "status": result.status,
        "confidence": result.confidence,
    }
    if result.missing_data:
        feedback["missing_data"] = [str(value)[:120] for value in result.missing_data[:5]]
    diagnostics = []
    candidates = [
        *([result.summary] if result.status == "unavailable" and result.summary else []),
        *result.warnings[:4],
    ]
    for warning in candidates:
        item = _query_failure_feedback({}, warning)
        # Generic warnings do not help repair a query and could contain stale
        # incident text. Keep only recognized operational diagnostics.
        if item.get("diagnostic") != "query failed":
            diagnostics.append(item)
    if diagnostics:
        feedback["execution_diagnostics"] = diagnostics
    return feedback


def _record_blackboard(blackboard: Any, result: CollectorResult, target: AnalysisTarget) -> None:
    method = getattr(blackboard, "add_result", None)
    if not callable(method):
        return
    entity = next(
        (
            f"{key}:{value}"
            for key in ("pod", "node", "workload_name", "service", "storage_claim", "namespace")
            if (value := str(getattr(target, key, "") or "").strip())
        ),
        "",
    )
    causal_window = causal_evidence_time_range(target) or {}
    try:
        method(
            result.agent,
            result,
            entity=entity,
            timestamp=str(getattr(target, "fired_at", "") or ""),
            observed_window_start=str(causal_window.get("start") or ""),
            observed_window_end=str(causal_window.get("end") or ""),
        )
    except TypeError:
        # Compatibility with custom blackboards that only implement the
        # original two-argument protocol. The built-in board always receives
        # the historical window above.
        try:
            method(result.agent, result)
        except Exception:  # noqa: BLE001 - shared reasoning is advisory
            return
    except Exception:  # noqa: BLE001 - shared reasoning is advisory
        return


def _blackboard_prompt_view(blackboard: Any, target: AnalysisTarget) -> list[dict[str, Any]]:
    method = getattr(blackboard, "prompt_view", None)
    if not callable(method):
        return []
    hints = [
        f"{key}:{value}"
        for key in ("pod", "node", "workload_name", "namespace")
        if (value := str(getattr(target, key, "") or "").strip())
    ]
    try:
        view = method(entity_hints=hints, limit=12)
    except Exception:  # noqa: BLE001
        return []
    return view if isinstance(view, list) else []


_EXTERNAL_HINT_DOMAINS = frozenset(_DOMAIN_FOCUS)
_EXTERNAL_HINT_ROUTING = {
    "kubernetes": frozenset({"containerd", "kubelet", "kubernetes", "k8s", "pod"}),
    "system": frozenset({"nfs", "filesystem", "driver", "nvlink", "kernel"}),
    "loki": frozenset({"log", "logs", "logging", "loki"}),
    "runai": frozenset({"runai", "scheduler", "quota", "queue", "project"}),
    "prometheus": frozenset({"scheduler", "quota", "queue", "project", "metric", "metrics"}),
}


def _external_case_hints_for_domain(
    agent: str, hints: list[dict[str, Any]] | None
) -> list[dict[str, str]]:
    """Route leads by canonical component token; unknown tokens remain advisory to all."""
    routed: list[dict[str, str]] = []
    for hint in hints or []:
        if not isinstance(hint, dict):
            continue
        action = " ".join(str(hint.get("normalized_action") or "").split())[:500]
        case_id = " ".join(str(hint.get("case_id") or "").split())[:180]
        raw_tokens = hint.get("canonical_component_tokens")
        tokens = {
            token
            for value in (raw_tokens if isinstance(raw_tokens, list) else [])
            for token in re.findall(r"[a-z0-9]+", str(value).lower())
        }
        destinations = {
            domain
            for domain, routing_tokens in _EXTERNAL_HINT_ROUTING.items()
            if tokens & routing_tokens
        }
        if not destinations:
            destinations = set(_EXTERNAL_HINT_DOMAINS)
        if action and case_id and agent in destinations:
            routed.append({"case_id": case_id, "normalized_action": action})
    return routed[:3]


def _ontology_guidance(
    plan: InvestigationPlan | None, *, external_case_hints: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Bounded, source-scoped TypeDB guidance for one evidence agent.

    The evidence agents receive the runbook as hypotheses and questions, never as
    executable commands. Their domain tool registry remains the enforcement point
    for read-only access.
    """
    directive = plan.diagnostic_directive if plan else {}
    if not isinstance(directive, dict):
        hints = _external_case_hints_for_guidance(external_case_hints)
        return {"external_case_investigation_leads": hints} if hints else {}

    def strings(key: str, limit: int) -> list[str]:
        values = directive.get(key) or []
        if not isinstance(values, list):
            return []
        return [str(value)[:500] for value in values if str(value).strip()][0:limit]

    guidance = {
        "source": str(directive.get("source") or ""),
        "path": strings("path", 6),
        "questions": strings("questions", 4),
        "checks": strings("checks", 4),
        "interpretation": strings("interpretation", 4),
        "avoid": strings("avoid", 4),
        "probes": [item for item in (directive.get("probes") or []) if isinstance(item, dict)][:4],
        "disconfirm": strings("disconfirm", 4),
        "competing_hypotheses": [
            item for item in (directive.get("competing_hypotheses") or []) if isinstance(item, dict)
        ][:4],
        "candidate_family": str(directive.get("provisional_family") or ""),
        "collector": str(directive.get("collector") or ""),
        "primary": bool(directive.get("primary")),
        "collector_instruction": str(directive.get("collector_instruction") or ""),
    }
    hints = _external_case_hints_for_guidance(external_case_hints)
    if hints:
        guidance["external_case_investigation_leads"] = hints
    return {key: value for key, value in guidance.items() if value not in ("", [], None)}


def _external_case_hints_for_guidance(
    hints: list[dict[str, Any]] | None,
) -> list[dict[str, str]]:
    return [
        {
            "label": (
                "Investigation leads from a similar historical external case — "
                "unverified hypotheses, not evidence"
            ),
            "case_id": hint["case_id"],
            "normalized_action": hint["normalized_action"],
        }
        for hint in (hints or [])[:3]
        if isinstance(hint, dict)
        and isinstance(hint.get("case_id"), str)
        and isinstance(hint.get("normalized_action"), str)
    ]


def _capped_json_prompt(
    stable: dict[str, Any],
    variable: dict[str, Any],
    *,
    max_chars: int,
    trim_keys: tuple[str, ...],
) -> str:
    variable = {
        key: list(value) if isinstance(value, list) else value for key, value in variable.items()
    }
    payload = {**stable, **variable}
    text = json.dumps(payload, default=str, ensure_ascii=False)
    while len(text) > max_chars:
        for key in trim_keys:
            value = variable.get(key)
            if isinstance(value, list) and len(value) > 1:
                variable[key] = value[1:]
                payload = {**stable, **variable}
                text = json.dumps(payload, default=str, ensure_ascii=False)
                break
        else:
            break
    if len(text) <= max_chars:
        return text
    marker = '"...truncated older prompt context..."'
    tail = max_chars // 4
    head = max_chars - tail - len(marker)
    return text[:head] + marker + text[-tail:]


def _compact_value(value: Any, *, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(value)
    return " ".join(text.split())[:limit]


def _artifact_prompt_item(art: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "type": art.type,
        "status": art.status,
        "summary": (art.summary or "")[:300],
    }
    if art.highlights:
        item["highlights"] = art.highlights[:6]
    if art.result is not None:
        item["result"] = _compact_value(observed_payload(art.result), limit=900)
    return item


def _artifact_is_evidence(art: Any) -> bool:
    return getattr(art, "status", "") in ("ok", "partial")


def _string_leaf_text(value: Any, *, limit: int = 1200) -> str:
    leaves: list[str] = []

    def walk(node: Any) -> None:
        if len(" ".join(leaves)) >= limit:
            return
        if isinstance(node, str):
            leaves.append(node)
        elif isinstance(node, dict):
            for child in node.values():
                walk(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                walk(child)

    walk(value)
    return " ".join(" ".join(leaves).split())[:limit]


def _artifact_architecture_text(art: Any) -> str:
    if not _artifact_is_evidence(art):
        return ""
    parts = [art.summary or ""]
    if art.highlights:
        parts.append(" ".join(map(str, art.highlights[:6])))
    if art.result is not None:
        parts.append(_string_leaf_text(observed_payload(art.result)))
    return " ".join(part for part in parts if part)


def _implicated_architecture(
    settings: Settings, result: CollectorResult, target: AnalysisTarget
) -> list[str]:
    """Topology lines for the platform components this incident implicates.

    A component is implicated when its name appears in the target identifiers
    (workload/pod/alert) or this agent's evidence text. Ranked by relevance —
    target-identifier matches (the alert's actual subject) before incidental
    evidence mentions, more specific names first, and names subsumed by a more
    specific match are dropped — so a broad evidence sweep can't crowd the
    subject component out of the cap. Each implicated component contributes its
    failure effect plus its dependency check order — a deterministic slice of
    runai_architecture.yaml, no knowledge-graph round-trip. Empty for pure
    user-workload incidents (correct: a user's training job is not a platform
    component)."""
    from app.knowledge import dependency_path, load_architecture

    components = load_architecture(getattr(settings, "architecture_file", ""))
    if not components:
        return []
    target_text = " ".join([target.workload_name, target.pod, target.alert_name]).lower()
    evidence_text = " ".join(
        [result.summary or "", *(_artifact_architecture_text(art) for art in result.artifacts[-8:])]
    ).lower()
    ranked: list[tuple[int, int, str]] = []
    for name in components:
        lowered = name.lower()
        if lowered in target_text:
            ranked.append((0, -len(name), name))
        elif _component_mentioned_as_evidence(evidence_text, lowered):
            ranked.append((1, -len(name), name))
    ranked.sort()
    rank_of = {name: bucket for bucket, _, name in ranked}
    implicated = [name for _, _, name in ranked]
    # A name is subsumed only by a more specific match of EQUAL OR BETTER rank —
    # an incidental evidence mention must never eat the alert's target match.
    implicated = [
        name
        for name in implicated
        if not any(
            other != name and name.lower() in other.lower() and rank_of[other] <= rank_of[name]
            for other in implicated
        )
    ]
    lines: list[str] = []
    seen: set[str] = set()
    for name in implicated[:3]:
        chain = dependency_path(components, name)
        if len(chain) > 1:
            lines.append(f"{name} check order: " + " → ".join(chain))
        for dep in chain[:4]:
            if dep in seen:
                continue
            seen.add(dep)
            entry = components.get(dep) or {}
            effect = entry.get("failure_effect") or entry.get("purpose") or ""
            if effect:
                lines.append(f"{dep}: {effect}")
    return lines[:10]


_HEALTHY_COMPONENT_SUFFIX_RE = re.compile(
    r"^\W*(?:is|are|was|were|looks?|looked)?\s*"
    r"(?:ok|healthy|running|ready|stable|normal|reachable|up)\b"
    r"|^\W*(?:has|had|shows?|showed|reports?|reported)?\s*(?:no|zero|0)\s+"
    r"(?:issues?|errors?|restarts?|failures?|problems?|warnings?|matching\s+errors)\b"
    r"|^\W*(?:logs?\s+)?(?:and\s+)?found\s+(?:no|zero|0)\s+"
    r"(?:matching\s+)?(?:errors?|issues?|failures?)\b"
    r"|^\W*(?:not\s+implicated|unrelated|excluded)\b"
    r"|^\W*(?:errors?|issues?|failures?|problems?)\s+(?:were\s+)?ruled\s+out\b"
)
_HEALTHY_COMPONENT_PREFIX_RE = re.compile(
    r"\b(?:ok|healthy|running|ready|stable|normal|reachable|up)"
    r"(?:\s+components?)?\W+(?:[\w-]+\W+){0,4}$"
    r"|\b(?:no|without)\s+"
    r"(?:issues?|errors?|restarts?|failures?|problems?|warnings?)\s+"
    r"(?:in|with|for|on)\b.{0,80}$"
)
_CONTRAST_WORD_RE = re.compile(r"\b(?:but|however|except|though|yet)\b")
_NON_EVIDENCE_COMPONENT_PREFIX_RE = re.compile(
    r"\b(?:docs?\s+example|runbook\s+example|sample\s+(?:payload|log\s+line)|"
    r"example\s+alert|question|template\s+includes|playbook\s+mentions|"
    r"todo\s+check|check\s+for)\b"
)
_UNHEALTHY_COMPONENT_SUFFIX_RE = re.compile(
    r"^\W*(?:is|are|was|were|looks?|looked)?\s*"
    r"(?:not\s+(?:ok|healthy|running|ready|stable|normal|reachable|up)|"
    r"unhealthy|disconnected|unavailable|down|failing|failed|error|errors?)\b"
)


def _component_mentioned_as_evidence(text: str, component: str) -> bool:
    from app.knowledge import _keyword_negated

    for match in re.finditer(re.escape(component), text):
        prefix = text[max(0, match.start() - 80) : match.start()]
        suffix = text[match.end() : match.end() + 80]
        prefix_clause = re.split(r"[.;\n]", prefix)[-1]
        suffix_clause = re.split(r"[.;\n]", suffix)[0]
        if _NON_EVIDENCE_COMPONENT_PREFIX_RE.search(prefix_clause):
            continue
        if _HEALTHY_COMPONENT_SUFFIX_RE.match(suffix_clause) or (
            _HEALTHY_COMPONENT_PREFIX_RE.search(prefix_clause)
            and not _CONTRAST_WORD_RE.search(prefix_clause)
        ):
            continue
        if _keyword_negated(text, match.start(), match.end()) and not (
            _UNHEALTHY_COMPONENT_SUFFIX_RE.match(suffix_clause)
        ):
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Domain tools. Each: async (settings, target, args) -> {query, summary, error?, result?}


# Valid metric-name reference, spliced into the metric-querying tool descriptions
# (rendered into both the drilldown and chat LLM system prompts) so the model uses
# real names instead of inventing ones that 400. PromQL series are the ones this
# agent already queries (known-present in this deployment).
_KNOWN_PROMQL_SERIES = (
    "runai_queue_allocated_gpus, runai_queue_requested_gpus, "
    "runai_project_allocated_gpus, runai_project_requested_gpus, "
    "kube_pod_status_phase, kube_pod_container_status_restarts_total, "
    "container_memory_working_set_bytes, container_cpu_usage_seconds_total"
)
def _domain_tools(settings: Settings) -> dict[str, dict[str, dict[str, Any]]]:
    """Per-agent tool registries — THE scoping boundary between domains."""
    change_sources = "all|controller|pod|event"
    if getattr(settings, "enable_helm_change_detection", False):
        change_sources += "|helm"
    registry: dict[str, dict[str, dict[str, Any]]] = {
        "kubernetes": {
            "k8s_read": {
                "description": (
                    "Read-only get/list of one Kubernetes kind. args: "
                    f"kind (one of: {', '.join(sorted(_READ_KINDS))}), "
                    "namespace?, name?, label_selector?. A named Pod is always "
                    "promoted to full YAML + describe/events automatically."
                ),
                "call": _tool_k8s_read,
            },
            "k8s_logs": {
                "description": (
                    "Read a pod's container logs (tail). USE THIS to inspect what a pod "
                    "actually logged. args: pod, namespace, container? (defaults to the "
                    "pod's main container), tail? (line count), previous? (true for the "
                    "prior terminated container instance)."
                ),
                "call": _tool_k8s_logs,
            },
            "k8s_describe": {
                "description": (
                    "Describe one object: its full spec/status PLUS its events (like "
                    "`kubectl describe`). Best for a Pod's waiting/terminated reason, "
                    "restart count, last-state exit code and scheduling events. args: "
                    "kind, name, namespace?"
                ),
                "call": _tool_k8s_describe,
            },
            "k8s_change_timeline": {
                "description": (
                    "Read a bounded Kubernetes change timeline for controller/pod/event "
                    "metadata. USE THIS for deployment or rollout history; do not invent a "
                    f"deployment_history resource. args: source ({change_sources}), "
                    "component?, lookback_seconds? (60..86400; for historical alerts it widens backward from fired time)"
                ),
                "call": _tool_k8s_change_timeline,
            },
        },
        "system": {
            "system_log_query": {
                "description": (
                    "Read one bounded, metadata-only host log observation for the alert node. "
                    "No raw log body is returned. args: source "
                    "(dmesg|journal|syslog|fabricmanager|nvidia-smi|nvlink), "
                    "node? (must equal the resolved alert node), lookback_seconds? "
                    "(60..86400), lines? (1..1000), grep? (bounded literal). For a past "
                    "incident prefer journal or fabricmanager, which are queried with the incident "
                    "start/end. dmesg, syslog, nvidia-smi, and nvlink are current-state snapshots."
                ),
                "call": _tool_system_log_query,
            }
        },
        "change": {
            "change_query": {
                "description": (
                    "Read one bounded, body-free change timeline inside the resolved alert "
                    "namespace/node and incident window. args: source "
                    "(all|controller|pod|node_condition|event"
                    + ("|helm" if getattr(settings, "enable_helm_change_detection", False) else "")
                    + "), component?, lookback_seconds? (60..86400; historical lookback is anchored to fired time), limit? (1..20)."
                ),
                "call": _tool_change_query,
            }
        },
    }
    if settings.enable_pod_exec:
        registry["kubernetes"]["k8s_exec"] = {
            "description": (
                "Run ONE read-only diagnostic command inside a container via the alert "
                "pod's exec — a single argv, NO shell (so no pipe `|`, redirect `>`, or "
                "`&&`). Inspect live state as the situation needs: nvidia-smi, ping, "
                "cat /proc/meminfo, ps, ss, ip addr, dig, curl, df -h, free -h, … args: "
                "pod, namespace, command (argv list), container?. Destructive/mutating "
                "commands (rm, kill, mv, dd, chmod, mount, systemctl, …) and shells/"
                "interpreters are refused."
            ),
            "call": _tool_k8s_exec,
        }
    if settings.prometheus_mcp_url or settings.prometheus_url:
        registry["prometheus"] = {
            "promql_query": {
                "description": (
                    "One MCP-first PromQL instant query against cluster metrics. args: "
                    "query (PromQL, e.g. 'rate(kube_pod_container_status_restarts_"
                    'total{namespace="x"}[15m])\'). '
                    f"Prefer these known-present series: {_KNOWN_PROMQL_SERIES}. "
                    "Use exact metric names — an invented/misspelled name 400s."
                ),
                "call": _tool_promql,
            }
        }
    if settings.loki_mcp_url or settings.loki_url:
        registry["loki"] = {
            "logql_query": {
                "description": (
                    "One MCP-first LogQL range query against Loki (recent window, backward). "
                    'args: query (LogQL, e.g. \'{namespace="runai"} |~ "(?i)(error|panic)"\'). '
                    "Never add sort/order by or | limit; the API controls those."
                ),
                "call": _tool_logql,
            }
        }
    if settings.runai_mcp_url:
        registry["runai"] = {
            "runai_workload_summary": {
                "description": (
                    "Read the official Run:ai MCP workload summary, scoped to the alert's "
                    "project when present. No arguments."
                ),
                "call": _tool_runai_workload_summary,
            },
            "runai_workload_status": {
                "description": (
                    "Read the official Run:ai MCP status for the alert's immutable Run:ai "
                    "workload ID. No arguments; unavailable when the alert has no ID."
                ),
                "call": _tool_runai_workload_status,
            },
            "runai_workload_history": {
                "description": (
                    "Read the official Run:ai MCP lifecycle history and recent events "
                    "for the alert's immutable workload ID. No arguments."
                ),
                "call": _tool_runai_workload_history,
            },
            "runai_workload_pods": {
                "description": (
                    "Read the official Run:ai MCP pod placement and allocation view for "
                    "the alert's immutable workload ID. No arguments."
                ),
                "call": _tool_runai_workload_pods,
            },
            "runai_workload_spec": {
                "description": (
                    "Read the official Run:ai MCP submitted spec, allocated resources, "
                    "placement, and pending messages for the alert workload. No arguments."
                ),
                "call": _tool_runai_workload_spec,
            },
            "runai_workload_metrics": {
                "description": (
                    "Read official Run:ai MCP workload metrics over the incident window "
                    "for the alert's immutable workload ID. No arguments."
                ),
                "call": _tool_runai_workload_metrics,
            },
            "runai_project_resources": {
                "description": (
                    "Read the official Run:ai MCP resource/quota view for the alert's "
                    "project. No arguments; unavailable when the alert has no project."
                ),
                "call": _tool_runai_project_resources,
            },
            "runai_project_metrics": {
                "description": (
                    "Read official Run:ai MCP allocation/utilization metrics over the "
                    "incident window for the alert's project. No arguments."
                ),
                "call": _tool_runai_project_metrics,
            },
            "runai_workload_effective_policy": {
                "description": (
                    "Read official Run:ai MCP effective policy rules and defaults for "
                    "workload types in the alert's project. No arguments; unavailable "
                    "when the alert has no project."
                ),
                "call": _tool_runai_workload_effective_policy,
            },
            "runai_department_resources": {
                "description": (
                    "Read official Run:ai MCP department quota by node pool. No "
                    "arguments; reads all departments when the alert has no department "
                    "label."
                ),
                "call": _tool_runai_department_resources,
            },
            "runai_cluster_physical_inventory": {
                "description": (
                    "Read official Run:ai MCP GPU-node/model physical inventory and "
                    "total, allocatable, allocated, and free GPUs. No arguments."
                ),
                "call": _tool_runai_cluster_physical_inventory,
            },
            "runai_cluster_infrastructure_health": {
                "description": (
                    "Read official Run:ai MCP degraded nodes and their Kubernetes "
                    "conditions and taints. No arguments."
                ),
                "call": _tool_runai_cluster_infrastructure_health,
            },
            "runai_cluster_metrics": {
                "description": (
                    "Read official Run:ai MCP GPU/CPU capacity and utilization trends "
                    "over the incident window. No arguments."
                ),
                "call": _tool_runai_cluster_metrics,
            },
            "runai_node_pools": {
                "description": (
                    "List Run:ai node pools available to the configured identity. "
                    "No arguments."
                ),
                "call": _tool_runai_node_pools,
            },
            "runai_node_pods": {
                "description": (
                    "Read official Run:ai MCP pods and workload allocations on the alert's "
                    "node. No arguments; unavailable when the alert has no node."
                ),
                "call": _tool_runai_node_pods,
            },
        }
    sql_dsn = settings.runai_db_dsn or settings.postgres_dsn
    if settings.postgres_mcp_url or sql_dsn:
        if settings.runai_db_dsn:
            db_desc = (
                "the Run:ai CONTROL-PLANE database (platform schemas: workloads, "
                "clusters, audit, authorization, org units, ...)"
            )
            # Schema ownership from the curated architecture topology, so the
            # loop knows WHERE to look without a discovery round-trip.
            schemas = _schema_ownership(settings)
            if schemas:
                db_desc += ". Schema ownership: " + "; ".join(
                    f"{schema} = {owner}" for schema, owner in schemas
                )
        else:
            db_desc = "the RCA store database (incidents, alerts, analysis runs, feedback)"
        registry["postgres"] = {
            "sql_select": {
                "description": (
                    f"One read-only SQL SELECT against {db_desc}. Discover tables first "
                    "via information_schema.tables / information_schema.columns, then "
                    "query the relevant rows. Single statement, SELECT/WITH only, runs "
                    "in a READ ONLY transaction, auto 'LIMIT 50'. args: query (SQL)"
                ),
                "call": _tool_sql_select,
            }
        }
    return registry


def _schema_ownership(settings: Settings) -> list[tuple[str, str]]:
    """(schema, owning component) pairs from the curated architecture topology."""
    from app.knowledge import load_architecture

    components = load_architecture(getattr(settings, "architecture_file", ""))
    return sorted(
        (entry["owns_schema"], name)
        for name, entry in components.items()
        if entry.get("owns_schema")
    )


def _title(settings: Settings, ko: str, en: str) -> str:
    return ko if getattr(settings, "language", "en") == "ko" else en


async def _tool_k8s_read(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    kind = str(args.get("kind") or "")
    namespace = str(args.get("namespace") or "")
    name = str(args.get("name") or "")
    label_selector = str(args.get("label_selector") or "")
    # A named Pod read must not depend on the model remembering to pick the
    # separate describe tool.  Promote it deterministically to the same full
    # YAML + filtered Events inspection used by the base collector and shared
    # investigator.  This closes the last path that still emitted a compact
    # ``kubectl get pods <name>`` artifact with lifecycle fields truncated.
    if resolve_read_kind(kind) == "pods" and name:
        item = await k8s_describe(
            settings,
            "pods",
            namespace=namespace,
            name=name,
            time_range=incident_time_range(target),
        )
        error = item.get("error")
        events = item.get("events") or []
        return {
            "query": pod_inspection_repr(namespace, name),
            "title": _title(settings, "Pod YAML + 상세 점검", "Pod YAML + describe"),
            "summary": str(error) if error else f"pods/{name}, {len(events)} event(s)",
            "error": error,
            "result": item,
            **({"mcp_fallback": item["mcp_fallback"]} if item.get("mcp_fallback") else {}),
        }
    # k8s_read is MCP-first with direct fallback — transport policy lives THERE,
    # so every k8s read path (followup / investigation / drill-down) shares it.
    item = await k8s_read(
        settings, kind, namespace=namespace, name=name, label_selector=label_selector
    )
    error = item.get("error")
    summary = str(error) if error else f"HTTP {item.get('status_code')}"
    return {
        # The real command an operator would have typed, not a param dump.
        "query": kubectl_repr(kind, namespace=namespace, name=name, label_selector=label_selector),
        "title": kind_lookup_title(kind, getattr(settings, "language", "en")),
        "summary": summary,
        "error": error,
        "result": item,
        # Transport note stays OUT of summary: artifact summaries feed the
        # ranker/signature matchers, and "no route to host" toward OUR MCP
        # service must not score as cluster-network evidence. The drill-down
        # loop surfaces this via collector warnings instead.
        **({"mcp_fallback": item["mcp_fallback"]} if item.get("mcp_fallback") else {}),
    }


async def _tool_k8s_change_timeline(
    settings: Settings, target: AnalysisTarget, args: dict
) -> dict:
    return await _tool_change_query(settings, target, args)


async def _tool_change_query(
    settings: Settings, target: AnalysisTarget, args: dict
) -> dict:
    # ``change_query`` constructs and bounds its own observation contract:
    # target correlation and the incident window are verified by the collector.
    # Mark that *adapter-produced* envelope explicitly, so a similarly named
    # field in arbitrary remote JSON never gains causal authority.
    outcome = await change_query(settings, target, args)
    if isinstance(outcome, dict) and isinstance(outcome.get("observation"), dict):
        outcome["_verified_observation"] = _VERIFIED_OBSERVATION
    return outcome


async def _tool_system_log_query(
    settings: Settings, target: AnalysisTarget, args: dict
) -> dict:
    # The system adapter returns metadata counts/signal categories only; raw
    # host log bodies never reach this loop. Mark only its adapter-built scope
    # and incident-window verdict as trusted evidence semantics.
    outcome = await system_log_query(settings, target, args)
    if isinstance(outcome, dict) and isinstance(outcome.get("observation"), dict):
        outcome["_verified_observation"] = _VERIFIED_OBSERVATION
    return outcome


async def _tool_k8s_logs(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    pod = str(args.get("pod") or args.get("name") or target.pod or "")
    namespace = str(args.get("namespace") or target.namespace or "")
    container = str(args.get("container") or "")
    previous = args.get("previous") is True or str(args.get("previous") or "").lower() == "true"
    try:
        tail = int(args.get("tail") or 0)
    except (TypeError, ValueError):
        tail = 0
    time_range = incident_time_range(target)
    item = await k8s_logs(
        settings,
        namespace,
        pod,
        container=container,
        tail=tail,
        previous=previous,
        since_time=str((time_range or {}).get("start") or ""),
    )
    error = item.get("error")
    lines = item.get("lines") or []
    ns_flag = f" -n {namespace}" if namespace else ""
    c_flag = f" -c {container}" if container else ""
    title = _title(
        settings,
        "이전 컨테이너 로그" if previous else "Pod 로그",
        "Previous container logs" if previous else "Pod logs",
    )
    return {
        "query": f"kubectl logs {pod}{ns_flag}{c_flag}" + (" --previous" if previous else ""),
        "title": title,
        "summary": str(error) if error else f"{len(lines)} log line(s)",
        "error": error,
        "result": item,
        **({"mcp_fallback": item["mcp_fallback"]} if item.get("mcp_fallback") else {}),
    }


async def _tool_k8s_describe(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    kind = str(args.get("kind") or "")
    namespace = str(args.get("namespace") or target.namespace or "")
    name = str(args.get("name") or "")
    item = await k8s_describe(
        settings,
        kind,
        namespace=namespace,
        name=name,
        time_range=incident_time_range(target),
    )
    error = item.get("error")
    events = item.get("events") or []
    ns_flag = f" -n {namespace}" if namespace else ""
    return {
        "query": f"kubectl describe {kind} {name}{ns_flag}",
        "title": _title(settings, "리소스 상세 (describe)", "Describe resource"),
        "summary": str(error) if error else f"{kind}/{name}, {len(events)} event(s)",
        "error": error,
        "result": item,
        **({"mcp_fallback": item["mcp_fallback"]} if item.get("mcp_fallback") else {}),
    }


async def _tool_k8s_exec(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    pod = str(args.get("pod") or args.get("name") or target.pod or "")
    namespace = str(args.get("namespace") or target.namespace or "")
    container = str(args.get("container") or "")
    raw = args.get("command")
    command = raw if isinstance(raw, list) else str(raw or "").split()
    item = await k8s_exec(settings, namespace, pod, [str(c) for c in command], container=container)
    error = item.get("error")
    return {
        "query": f"kubectl exec {pod} -- {' '.join(str(c) for c in command)}",
        "title": _title(settings, "컨테이너 조회 (exec)", "Container exec"),
        "summary": str(error) if error else "exec ok",
        "error": error,
        "result": item,
    }


async def _tool_promql(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    promql, validation_error = _sanitize_metric_query(
        str(args.get("query") or ""), "promql_query"
    )
    title = _title(settings, "메트릭 조회 (PromQL)", "Metric query (PromQL)")
    if validation_error:
        return {"query": "", "title": title, "summary": validation_error, "error": validation_error}
    if not promql:
        return {
            "query": "",
            "title": title,
            "summary": "empty PromQL query",
            "error": "empty PromQL query",
        }
    if len(promql) > 600:
        return {
            "query": "",
            "title": title,
            "summary": "invalid query: exceeds 600 characters; shorten it",
            "error": "invalid query: exceeds 600 characters; shorten it",
        }
    fallback = ""
    time_range = incident_time_range(target)
    if settings.prometheus_mcp_url:
        try:
            item = await prom_mcp_query(
                settings,
                "drilldown",
                promql,
                time_range=time_range,
            )
            error = item.get("error")
            summary = str(error) if error else (
                ko_en(
                    settings,
                    "MCP query_prometheus 결과 0개 시리즈 — 메트릭 이름/레이블 매처를 확인하세요.",
                    "MCP query_prometheus returned 0 series — verify metric name/label matchers.",
                )
                if int(item.get("series_count") or 0) == 0
                else "MCP query_prometheus ok"
            )
            return {
                "query": promql,
                "title": title,
                "summary": summary,
                "error": error,
                "result": item,
            }
        except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
            fallback = mcp_fallback_warning(exc, source="Prometheus")
    else:
        fallback = f"{MCP_FALLBACK_WARNING}: PROMETHEUS_MCP_URL not configured"
    if not settings.prometheus_url:
        return {"query": promql, "title": title, "summary": fallback, "error": fallback}
    item = await prom_query(settings, "drilldown", promql, time_range=time_range)
    error = item.get("error")
    summary = str(error) if error else f"HTTP {item.get('status_code')}"
    return {
        "query": promql,
        "title": title,
        "summary": summary,
        "error": error,
        "result": item,
        **({"mcp_fallback": fallback} if fallback else {}),
    }


async def _tool_logql(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    logql, validation_error = _sanitize_metric_query(
        str(args.get("query") or ""), "logql_query"
    )
    title = _title(settings, "로그 조회 (LogQL)", "Log query (LogQL)")
    if validation_error:
        return {"query": "", "title": title, "summary": validation_error, "error": validation_error}
    if not logql:
        return {
            "query": "",
            "title": title,
            "summary": "empty LogQL query",
            "error": "empty LogQL query",
        }
    if len(logql) > 600:
        return {
            "query": "",
            "title": title,
            "summary": "invalid query: exceeds 600 characters; shorten it",
            "error": "invalid query: exceeds 600 characters; shorten it",
        }
    fallback = ""
    time_range = incident_time_range(target)
    if settings.loki_mcp_url:
        try:
            item = await loki_mcp_query(
                settings,
                "drilldown",
                logql,
                time_range=time_range,
            )
            error = item.get("error")
            return {
                "query": logql,
                "title": title,
                "summary": str(error) if error else f"{item.get('line_count', 0)} MCP log line(s)",
                "error": error,
                "result": item,
            }
        except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
            fallback = mcp_fallback_warning(exc, source="Loki")
    else:
        fallback = f"{MCP_FALLBACK_WARNING}: LOKI_MCP_URL not configured"
    if not settings.loki_url:
        return {"query": logql, "title": title, "summary": fallback, "error": fallback}
    headers, _warnings = _loki_headers(settings)
    response = await get_json(
        base_url=settings.loki_url,
        path="/loki/api/v1/query_range",
        timeout_seconds=settings.loki_timeout_seconds,
        params={
            "query": logql,
            "limit": str(settings.loki_query_limit),
            "direction": "BACKWARD",
            **(time_range or {}),
        },
        headers=headers,
        verify=mcp_tls_verify(),
    )
    if response.error or not response.ok or not _loki_native_response_complete(response.data):
        error = (
            response.error
            or (f"HTTP {response.status_code}" if not response.ok else "")
            or "Loki response missing successful data.result"
        )
        return {
            "query": logql,
            "title": title,
            "summary": error,
            "error": error,
            **({"mcp_fallback": fallback} if fallback else {}),
        }
    lines = _sample_lines(_loki_streams(response.data), limit=10)
    summary = f"{len(lines)} sample log line(s)" if lines else "no matching log lines"
    return {
        "query": logql,
        "title": title,
        "summary": summary,
        "error": None,
        "result": {"lines": lines},
        **({"mcp_fallback": fallback} if fallback else {}),
    }


# --- read-only SQL (postgres agent) ----------------------------------------

_SQL_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|vacuum|"
    r"call|do|execute|set|listen|notify|lock|reindex|refresh|prepare|deallocate|"
    r"merge|into|pg_sleep|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|"
    r"pg_rotate_logfile|pg_create_restore_point|pg_start_backup|pg_stop_backup|"
    r"nextval|setval|pg_advisory_lock|pg_try_advisory_lock|pg_notify|"
    r"lo_import|lo_export|pg_read_file|pg_read_binary_file|pg_ls_dir|"
    r"pg_ls_waldir|pg_ls_logdir|pg_ls_archive_statusdir|pg_stat_file|"
    r"dblink|dblink_exec)\b",
    re.IGNORECASE,
)
_SQL_DOLLAR_QUOTE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")


def _mask_sql_literals(sql: str) -> str:
    chars = list(sql)
    i = 0
    while i < len(sql):
        char = sql[i]
        if char == "'":
            quote = "'"
            chars[i] = " "
            i += 1
            while i < len(sql):
                chars[i] = " "
                if sql[i] == quote:
                    if i + 1 < len(sql) and sql[i + 1] == quote:
                        chars[i + 1] = " "
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if char == "$":
            match = _SQL_DOLLAR_QUOTE_RE.match(sql, i)
            if match:
                end = sql.find(match.group(0), match.end())
                if end >= 0:
                    end += len(match.group(0))
                    chars[i:end] = " " * (end - i)
                    i = end
                    continue
        i += 1
    return "".join(chars)


def _validate_select(sql: str) -> tuple[str | None, str]:
    """(error, normalized_sql). Fail-closed: single statement, SELECT/WITH only."""
    text = (sql or "").strip()
    if not text:
        return "empty SQL query", text
    masked = _mask_sql_literals(text).rstrip()
    text = text.rstrip()
    if re.search(r"--|/\*", masked):
        return "SQL comments are not allowed", text
    if masked.endswith(";"):
        text = text[: len(masked) - 1].rstrip()
        masked = masked[:-1].rstrip()
    if ";" in masked:
        return "a single SQL statement is required", text
    if not re.match(r"(?i)^\s*(select|with)\b", masked):
        return "only SELECT/WITH queries are allowed", text
    match = _SQL_FORBIDDEN.search(masked)
    if match:
        return f"forbidden SQL keyword: {match.group(0)}", text
    return None, text


async def _run_select(dsn: str, sql: str, timeout: int) -> list[dict]:
    # Lazy import mirrors the postgres collector; READ ONLY transaction is the
    # second fence behind the syntactic guard (and a read-only DB role, ideally).
    import asyncpg

    from app.collectors.postgres import _record_to_dict

    conn = await asyncio.wait_for(asyncpg.connect(dsn, timeout=timeout), timeout=timeout + 1)
    try:
        async with conn.transaction(readonly=True):
            rows = await asyncio.wait_for(conn.fetch(sql), timeout=timeout)
        return [_record_to_dict(row) for row in rows[:50]]
    finally:
        await conn.close()


async def _run_select_mcp(settings: Settings, sql: str) -> list[dict]:
    from app.collectors.postgres import _mcp_postgres_rows

    result = await mcp_call(settings.postgres_mcp_url, "query", {"sql": sql})
    error = mcp_error(result)
    if error:
        raise RuntimeError(error)
    data = mcp_tool_json(result)
    if isinstance(data, dict) and "raw" in data:
        raise RuntimeError("MCP result was not JSON")
    rows = _mcp_postgres_rows(data)
    if rows is None:
        raise RuntimeError("Postgres MCP response missing a recognized row result")
    return [row for row in rows[:50] if isinstance(row, dict)]


def _postgres_rows(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("rows", "result", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        if all(not isinstance(value, (list, dict)) for value in data.values()):
            return [data]
    return []


async def _tool_sql_select(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    title = _title(settings, "DB 조회 (SQL)", "Database query (SQL)")
    error, sql = _validate_select(str(args.get("query") or ""))
    if error:
        return {"query": sql, "title": title, "summary": error, "error": error}
    if not re.search(r"(?i)\blimit\s+\d+(?:\s+offset\s+\d+)?\s*$", sql):
        sql = f"{sql} LIMIT 50"
    fallback = ""
    if settings.postgres_mcp_url:
        try:
            rows = await _run_select_mcp(settings, sql)
            return {
                "query": sql,
                "title": title,
                "summary": f"{len(rows)} MCP row(s)",
                "error": None,
                "result": {"rows": rows},
            }
        except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
            fallback = mcp_fallback_warning(exc, source="Postgres")
    else:
        fallback = f"{MCP_FALLBACK_WARNING}: POSTGRES_MCP_URL not configured"
    dsn = settings.runai_db_dsn or settings.postgres_dsn
    if not dsn:
        return {"query": sql, "title": title, "summary": fallback, "error": fallback}
    rows = await _run_select(dsn, sql, settings.postgres_timeout_seconds)
    return {
        "query": sql,
        "title": title,
        "summary": f"{len(rows)} row(s)",
        "error": None,
        "result": {"rows": rows},
        **({"mcp_fallback": fallback} if fallback else {}),
    }


async def _mcp_call(
    settings: Settings, tool: str, arguments: dict, url: str = ""
) -> Any:
    # NVIDIA's official HTTP MCP is an OAuth-protected resource. Reuse exactly
    # the Run:ai token source used by the direct collector, rather than making
    # an unauthenticated in-cluster call just because the service is ClusterIP.
    from app.collectors.runai import _runai_headers

    headers, _warnings = await _runai_headers(settings)
    if not headers.get("Authorization"):
        raise RuntimeError(
            "Run:ai MCP authentication is unavailable; configure RUNAI_BEARER_TOKEN "
            "or RUNAI_CLIENT_ID and RUNAI_CLIENT_SECRET"
        )
    return await mcp_call(url or settings.runai_mcp_url, tool, arguments, headers=headers)


async def _resolve_runai_cluster_id(settings: Settings, target: AnalysisTarget) -> str:
    """Resolve an alert's cluster name to the UUID required by official MCP tools."""
    if valid_official_workload_id(target.cluster):
        return target.cluster
    if not settings.runai_base_url:
        raise RuntimeError("Run:ai base URL is not configured; cannot resolve cluster ID")
    cache_key = (settings.runai_base_url, target.cluster)
    if cached := _RUNAI_CLUSTER_ID_CACHE.get(cache_key):
        return cached
    from app.collectors.runai import _runai_headers

    headers, _warnings = await _runai_headers(settings)
    if not headers.get("Authorization"):
        raise RuntimeError("Run:ai API authentication is unavailable; cannot resolve cluster ID")
    response = await get_json(
        base_url=settings.runai_base_url,
        path="/api/v1/clusters",
        timeout_seconds=settings.runai_timeout_seconds,
        headers=headers,
    )
    if not response.ok:
        raise RuntimeError(response.error or f"HTTP {response.status_code} resolving cluster ID")
    data = response.data
    rows = (
        data
        if isinstance(data, list)
        else data.get("clusters")
        if isinstance(data, dict)
        else None
    )
    clusters = [row for row in (rows or []) if isinstance(row, dict)]
    matches = [row for row in clusters if str(row.get("name") or "") == target.cluster]
    candidates = matches or (clusters if len(clusters) == 1 else [])
    if not candidates:
        raise RuntimeError(
            f"could not resolve Run:ai cluster ID for alert cluster {target.cluster!r}"
        )
    cluster_id = str(candidates[0].get("uuid") or candidates[0].get("id") or "")
    if not cluster_id:
        raise RuntimeError(
            f"Run:ai cluster {str(candidates[0].get('name') or target.cluster)!r} has no UUID"
        )
    _RUNAI_CLUSTER_ID_CACHE[cache_key] = cluster_id
    return cluster_id


async def _resolve_runai_project_id(settings: Settings, target: AnalysisTarget) -> str:
    """Resolve an alert's project name to the ID required by policy lookup."""
    if not target.project:
        raise RuntimeError("alert has no Run:ai project")
    if not settings.runai_base_url:
        raise RuntimeError("Run:ai base URL is not configured; cannot resolve project ID")
    cache_key = (settings.runai_base_url, target.project)
    if cached := _RUNAI_PROJECT_ID_CACHE.get(cache_key):
        return cached
    from app.collectors.runai import _runai_headers

    headers, _warnings = await _runai_headers(settings)
    if not headers.get("Authorization"):
        raise RuntimeError("Run:ai API authentication is unavailable; cannot resolve project ID")
    response = await get_json(
        base_url=settings.runai_base_url,
        path="/api/v1/org-unit/projects",
        timeout_seconds=settings.runai_timeout_seconds,
        headers=headers,
    )
    if not response.ok:
        raise RuntimeError(response.error or f"HTTP {response.status_code} resolving project ID")
    data = response.data
    rows = (
        data
        if isinstance(data, list)
        else data.get("projects")
        if isinstance(data, dict)
        else None
    )
    projects = [row for row in (rows or []) if isinstance(row, dict)]
    match = next((row for row in projects if str(row.get("name") or "") == target.project), None)
    if match is None:
        raise RuntimeError(
            f"could not resolve Run:ai project ID for alert project {target.project!r}"
        )
    project_id = str(match.get("id") or "")
    if not project_id:
        raise RuntimeError(f"Run:ai project {target.project!r} has no ID")
    _RUNAI_PROJECT_ID_CACHE[cache_key] = project_id
    return project_id


async def _official_runai_tool(
    settings: Settings,
    *,
    tool: str,
    arguments: dict[str, str],
    title_ko: str,
    title_en: str,
) -> dict:
    title = _title(settings, title_ko, title_en)
    query = f"MCP {tool}" + (f" {arguments}" if arguments else "")
    try:
        result = await _mcp_call(settings, tool, arguments)
    except Exception as exc:  # noqa: BLE001 - drill-down failure stays an artifact
        error = _safe_text(str(exc), limit=_RESULT_CHARS)
        return {"query": query, "title": title, "summary": error, "error": error}
    if getattr(result, "isError", False):
        error = mcp_error(result)
        return {"query": query, "title": title, "summary": error, "error": error}
    return {
        "query": query,
        "title": title,
        "summary": f"{tool} ok",
        "error": None,
        "result": _tool_json(result),
    }


async def _tool_runai_workload_summary(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    arguments = (
        {"orgType": "project", "orgName": target.project}
        if target.project
        else {}
    )
    return await _official_runai_tool(
        settings,
        tool="get_workloads_summary",
        arguments=arguments,
        title_ko="Run:ai 워크로드 요약",
        title_en="Run:ai workload summary",
    )


async def _tool_runai_workload_status(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    return await _official_workload_tool(
        settings,
        target,
        tool="get_workload_status",
        title_ko="Run:ai 워크로드 상태",
        title_en="Run:ai workload status",
    )


async def _tool_runai_workload_history(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    return await _official_workload_tool(
        settings,
        target,
        tool="get_workload_history",
        title_ko="Run:ai 워크로드 이력",
        title_en="Run:ai workload history",
    )


async def _tool_runai_workload_pods(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    return await _official_workload_tool(
        settings,
        target,
        tool="get_workload_pods",
        title_ko="Run:ai 워크로드 파드",
        title_en="Run:ai workload pods",
    )


async def _tool_runai_workload_spec(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    return await _official_workload_tool(
        settings,
        target,
        tool="get_workload_spec",
        title_ko="Run:ai 워크로드 명세",
        title_en="Run:ai workload spec",
    )


async def _tool_runai_workload_metrics(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    arguments: dict[str, str] = {}
    time_range = incident_time_range(target) or {}
    if time_range.get("start") and time_range.get("end"):
        arguments.update(
            {"start": str(time_range["start"]), "end": str(time_range["end"])}
        )
    return await _official_workload_tool(
        settings,
        target,
        tool="get_workload_metrics",
        title_ko="Run:ai 워크로드 메트릭",
        title_en="Run:ai workload metrics",
        extra_arguments=arguments,
    )


async def _official_workload_tool(
    settings: Settings,
    target: AnalysisTarget,
    *,
    tool: str,
    title_ko: str,
    title_en: str,
    extra_arguments: dict[str, str] | None = None,
) -> dict:
    title = _title(settings, title_ko, title_en)
    workload_id = target.runai_workload_id
    if not workload_id:
        error = "alert has no immutable Run:ai workload ID"
        return {
            "query": f"MCP {tool}",
            "title": title,
            "summary": error,
            "error": error,
        }
    if not valid_official_workload_id(workload_id):
        error = "alert Run:ai workload ID is not a UUID accepted by the official MCP"
        return {
            "query": f"MCP {tool}",
            "title": title,
            "summary": error,
            "error": error,
        }
    arguments = {"workloadId": workload_id, **(extra_arguments or {})}
    return await _official_runai_tool(
        settings,
        tool=tool,
        arguments=arguments,
        title_ko=title_ko,
        title_en=title_en,
    )


async def _tool_runai_project_resources(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    if not target.project:
        error = "alert has no Run:ai project"
        return {
            "query": "MCP list_project_resources",
            "title": _title(settings, "Run:ai 프로젝트 리소스", "Run:ai project resources"),
            "summary": error,
            "error": error,
        }
    return await _official_runai_tool(
        settings,
        tool="list_project_resources",
        arguments={"projectName": target.project},
        title_ko="Run:ai 프로젝트 리소스",
        title_en="Run:ai project resources",
    )


async def _tool_runai_project_metrics(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    if not target.project:
        error = "alert has no Run:ai project"
        return {
            "query": "MCP get_org_unit_metrics",
            "title": _title(settings, "Run:ai 프로젝트 메트릭", "Run:ai project metrics"),
            "summary": error,
            "error": error,
        }
    arguments = {"orgType": "project", "orgName": target.project}
    time_range = incident_time_range(target) or {}
    if time_range.get("start") and time_range.get("end"):
        arguments.update(
            {"start": str(time_range["start"]), "end": str(time_range["end"])}
        )
    return await _official_runai_tool(
        settings,
        tool="get_org_unit_metrics",
        arguments=arguments,
        title_ko="Run:ai 프로젝트 메트릭",
        title_en="Run:ai project metrics",
    )


async def _tool_runai_workload_effective_policy(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    if not target.project:
        error = "alert has no Run:ai project"
        return {
            "query": "MCP get_workload_effective_policy",
            "title": _title(
                settings, "Run:ai 워크로드 유효 정책", "Run:ai workload effective policy"
            ),
            "summary": error,
            "error": error,
        }
    kinds = {
        "training": "Training",
        "interactive": "Interactive",
        "inference": "Inference",
        "distributed": "Distributed",
    }
    kind = kinds.get(target.workload_type.casefold())
    if not kind:
        error = f"alert workload type is unusable for effective policy: {target.workload_type!r}"
        return {
            "query": "MCP get_workload_effective_policy",
            "title": _title(
                settings, "Run:ai 워크로드 유효 정책", "Run:ai workload effective policy"
            ),
            "summary": error,
            "error": error,
        }
    try:
        project_id = await _resolve_runai_project_id(settings, target)
    except Exception as exc:  # noqa: BLE001 - drill-down failure stays an artifact
        error = _safe_text(str(exc), limit=_RESULT_CHARS)
        return {
            "query": "MCP get_workload_effective_policy",
            "title": _title(
                settings, "Run:ai 워크로드 유효 정책", "Run:ai workload effective policy"
            ),
            "summary": error,
            "error": error,
        }
    return await _official_runai_tool(
        settings,
        tool="get_workload_effective_policy",
        arguments={"projectId": project_id, "kind": kind},
        title_ko="Run:ai 워크로드 유효 정책",
        title_en="Run:ai workload effective policy",
    )


async def _tool_runai_department_resources(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    arguments = {"departmentName": target.department} if target.department else {}
    return await _official_runai_tool(
        settings,
        tool="list_department_resources",
        arguments=arguments,
        title_ko="Run:ai 부서 리소스",
        title_en="Run:ai department resources",
    )


async def _tool_runai_cluster_physical_inventory(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    title_ko = "Run:ai 클러스터 물리 인벤토리"
    title_en = "Run:ai cluster physical inventory"
    try:
        cluster_id = await _resolve_runai_cluster_id(settings, target)
    except Exception as exc:  # noqa: BLE001 - drill-down failure stays an artifact
        error = _safe_text(str(exc), limit=_RESULT_CHARS)
        return {
            "query": "MCP get_cluster_physical_inventory",
            "title": _title(settings, title_ko, title_en),
            "summary": error,
            "error": error,
        }
    return await _official_runai_tool(
        settings,
        tool="get_cluster_physical_inventory",
        arguments={"clusterId": cluster_id},
        title_ko=title_ko,
        title_en=title_en,
    )


async def _tool_runai_cluster_infrastructure_health(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    title_ko = "Run:ai 클러스터 인프라 상태"
    title_en = "Run:ai cluster infrastructure health"
    try:
        cluster_id = await _resolve_runai_cluster_id(settings, target)
    except Exception as exc:  # noqa: BLE001 - drill-down failure stays an artifact
        error = _safe_text(str(exc), limit=_RESULT_CHARS)
        return {
            "query": "MCP get_cluster_infrastructure_health",
            "title": _title(settings, title_ko, title_en),
            "summary": error,
            "error": error,
        }
    return await _official_runai_tool(
        settings,
        tool="get_cluster_infrastructure_health",
        arguments={"clusterId": cluster_id},
        title_ko=title_ko,
        title_en=title_en,
    )


async def _tool_runai_cluster_metrics(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    title_ko = "Run:ai 클러스터 메트릭"
    title_en = "Run:ai cluster metrics"
    try:
        cluster_id = await _resolve_runai_cluster_id(settings, target)
    except Exception as exc:  # noqa: BLE001 - drill-down failure stays an artifact
        error = _safe_text(str(exc), limit=_RESULT_CHARS)
        return {
            "query": "MCP get_cluster_metrics",
            "title": _title(settings, title_ko, title_en),
            "summary": error,
            "error": error,
        }
    arguments: dict[str, str] = {"clusterId": cluster_id}
    time_range = incident_time_range(target) or {}
    if time_range.get("start") and time_range.get("end"):
        arguments.update(
            {"start": str(time_range["start"]), "end": str(time_range["end"])}
        )
    return await _official_runai_tool(
        settings,
        tool="get_cluster_metrics",
        arguments=arguments,
        title_ko=title_ko,
        title_en=title_en,
    )


async def _tool_runai_node_pools(
    settings: Settings, _target: AnalysisTarget, _args: dict
) -> dict:
    return await _official_runai_tool(
        settings,
        tool="list_node_pools",
        arguments={},
        title_ko="Run:ai 노드 풀",
        title_en="Run:ai node pools",
    )


async def _tool_runai_node_pods(
    settings: Settings, target: AnalysisTarget, _args: dict
) -> dict:
    if not target.node:
        error = "alert has no node"
        return {
            "query": "MCP get_node_pods",
            "title": _title(settings, "Run:ai 노드 파드", "Run:ai node pods"),
            "summary": error,
            "error": error,
        }
    return await _official_runai_tool(
        settings,
        tool="get_node_pods",
        arguments={"nodeName": target.node},
        title_ko="Run:ai 노드 파드",
        title_en="Run:ai node pods",
    )


def _safe_text(value: str, *, limit: int) -> str:
    text = " ".join(build_masker(()).mask_text(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
