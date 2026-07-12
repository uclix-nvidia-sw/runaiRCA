"""Per-collector autonomous drill-down loops (LLM-gated, read-only).

Each evidence agent (kubernetes / prometheus / loki / runai) runs its OWN small
bounded LLM loop after the base gather: it looks at ITS OWN evidence and decides
follow-up read-only queries in ITS OWN domain. Tool scoping is structural — each
loop receives only its domain's tool registry, so the kubernetes loop cannot
call the Run:ai API and vice versa. Follow-up results are appended to the
collector's artifacts, where the existing pipeline (masking, signature matching,
the verify pass, synthesis) consumes them with zero changes.

Best-effort like the central investigation loop: flag off (ENABLE_AGENT_DRILLDOWN),
no LLM, or ANY failure -> the base evidence stands. There is no fixed query or
step limit: a loop ends on `done`, a repeated query, or the analysis-wide
deadline. Read-only by construction:
the k8s tool is the allowlisted `k8s_read`, Run:ai calls are locked to GET under
/api/, PromQL/LogQL only hit query endpoints, and SQL is a single SELECT inside
a READ ONLY transaction (RUNAI_DB_DSN lets the postgres agent query the Run:ai
control-plane DB itself, not just health-check the RCA store). Untrusted
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
from typing import Any
from urllib.parse import unquote, urlencode

from app.collectors.base import (
    AnalysisTarget,
    CollectorResult,
    artifact,
    salient_markers,
    signals_line,
)
from app.collectors.http_json import get_json
from app.collectors.kubernetes import (
    _EXEC_ALLOWLIST,
    _READ_KINDS,
    k8s_describe,
    k8s_exec,
    k8s_logs,
    k8s_read,
    kind_lookup_title,
    kubectl_repr,
)
from app.collectors.loki import _loki_headers, _loki_streams, _sample_lines, loki_mcp_query
from app.collectors.prometheus import prom_mcp_query, prom_query
from app.collectors.runai_mcp import _tool_json, _tool_text
from app.config import Settings
from app.llm import complete_json, llm_configured
from app.masking import build_masker
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
)
from app.plan import InvestigationPlan
from app.services.probe_evaluation import evaluate_probe

_log = logging.getLogger(__name__)

_RESULT_CHARS = 1500  # per-query result excerpt fed back into the loop
_USER_PROMPT_CHARS = 6000


async def run_drilldowns(
    settings: Settings,
    results: list[CollectorResult],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    *,
    blackboard: Any = None,
) -> None:
    """Run every domain's drill-down loop concurrently. Never raises."""
    if not settings.enable_agent_drilldown or not llm_configured(
        settings, settings.llm_model_drilldown
    ):
        return
    registry = _domain_tools(settings)
    tasks = [
        _drill_one(
            settings,
            result,
            registry[result.agent],
            target,
            plan.for_collector(result.agent) if plan else None,
            blackboard=blackboard,
        )
        for result in results
        if result.agent in registry and result.status != "unavailable"
    ]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _drill_one(
    settings: Settings,
    result: CollectorResult,
    tools: dict[str, dict[str, Any]],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    *,
    blackboard: Any = None,
) -> None:
    """One agent's adaptive think->query->observe loop over its own evidence."""
    masker = _drilldown_masker(settings)
    try:
        architecture = _implicated_architecture(settings, result, target)
        history: list[dict[str, Any]] = []
        seen_queries: set[str] = set()
        # A TypeDB/YAML probe is executable only through this agent's existing
        # read-only registry.  Run it before asking the LLM to improvise a
        # query: the declarative probe is the durable operational knowledge,
        # while the LLM decides what additional discriminator is worthwhile.
        for query in _declared_probe_queries(plan, tools, target):
            key = _query_fingerprint(query)
            seen_queries.add(key)
            await _run_query(
                settings, result, tools, target, query, history, masker, blackboard=blackboard,
                artifact_type="ontology_probe",
            )
        step = 0
        while True:
            step += 1
            user_prompt = masker.mask_text(
                _user_prompt(result, target, plan, history, architecture, blackboard=blackboard)
            )
            decision = await complete_json(
                settings,
                system=_system_prompt(result.agent, tools),
                user=user_prompt,
                model=settings.llm_model_drilldown,
            )
            if decision is None:
                # An LLM transport/parse failure must be distinguishable from a
                # legitimate "done" — otherwise a dead LLM looks like a satisfied
                # agent and nobody notices drill-down never ran (the litellm
                # provider incident). Surface it in the report warnings.
                result.warnings.append(
                    f"{result.agent} drill-down stopped at step {step}: "
                    "LLM decision call failed"
                )
                break
            if not isinstance(decision, dict) or decision.get("action") != "query":
                _log.info(
                    "drilldown %s: done after %d follow-up quer(ies)",
                    result.agent,
                    len(history),
                )
                break
            queries = []
            for q in decision.get("queries") or []:
                if not isinstance(q, dict) or str(q.get("tool") or "") not in tools:
                    continue
                key = _query_fingerprint(q)
                if key in seen_queries:
                    continue
                seen_queries.add(key)
                queries.append(q)
            if not queries:
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
            for q in queries:
                await _run_query(
                    settings, result, tools, target, q, history, masker, blackboard=blackboard
                )
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


async def _run_query(
    settings: Settings,
    result: CollectorResult,
    tools: dict[str, dict[str, Any]],
    target: AnalysisTarget,
    query: dict[str, Any],
    history: list[dict[str, Any]],
    masker: Any,
    *,
    blackboard: Any = None,
    artifact_type: str = "drilldown_query",
) -> None:
    """Execute one registry-validated query and preserve its observation."""
    name = str(query.get("tool") or "")
    if name not in tools:
        return
    args = query.get("args") if isinstance(query.get("args"), dict) else {}
    outcome = await _call_tool_safely(tools[name]["call"], settings, target, args)
    outcome = masker.mask_object(outcome)
    if not isinstance(outcome, dict):
        outcome = {"error": "tool returned no result"}
    error = outcome.get("error")
    probe = query.get("_ontology_probe")
    if artifact_type == "ontology_probe" and isinstance(probe, dict):
        assessment = evaluate_probe(probe, outcome).as_dict()
        assessment["hypothesis_family"] = str(probe.get("hypothesis_family") or "")
        assessments = result.details.setdefault("ontology_probe_assessments", [])
        if isinstance(assessments, list):
            assessments.append(assessment)
    history_outcome = {"error": "query failed"} if error else outcome
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
    markers = [] if error else salient_markers(outcome.get("result"))
    summary = str(outcome.get("summary") or error or name)
    if markers:
        summary = f"{summary} — {signals_line(markers, getattr(settings, 'language', 'en'))}"
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
            result=outcome.get("result"),
        )
    )
    if artifact_type == "ontology_probe" and isinstance(probe, dict):
        assessments = result.details.get("ontology_probe_assessments")
        if isinstance(assessments, list) and assessments:
            assessments[-1]["artifact_index"] = len(result.artifacts) - 1
    _record_blackboard(blackboard, result, target)


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
        if "{{" in value or "}}" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
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
        query = {"tool": tool, "args": args, "_ontology_probe": raw_probe}
        fingerprint = _query_fingerprint(query)
        if fingerprint not in seen:
            seen.add(fingerprint)
            queries.append(query)
    return queries


def _query_fingerprint(query: dict[str, Any]) -> str:
    """Deduplicate execution identity, not internal ontology metadata."""
    return json.dumps(
        {key: value for key, value in query.items() if not str(key).startswith("_")},
        sort_keys=True,
        default=str,
    )


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
        "- Fetch data RELATED to the incident — the workload's controller, its "
        "project/queue, the Run:ai control-plane component involved, correlated "
        "namespaces and time windows — never your own datasource's health (the base "
        "collector already covered that).\n"
        "- KEEP GOING while a plausible in-domain cause is still untested, your key "
        "evidence is thin or ambiguous, or you have not yet found the ORIGIN (not just "
        "a downstream symptom). Do NOT stop at the first plausible-looking line. Answer "
        "action=done ONLY when your own domain is thoroughly covered and further queries "
        "would be redundant.\n"
        "- If ontology_guidance is supplied, turn its questions and checks into narrow "
        "queries using only your tools. Its candidate family is a hypothesis, not evidence: "
        "actively look for the listed disconfirmations too. Respect its avoid guidance and use "
        "its interpretation notes to classify ambiguous results. Never execute check prose as a "
        "command. If it includes structured probes, use only probes whose tool is in your "
        "registry and resolve their placeholders from the incident scope.\n"
        "- Stay strictly read-only and inside your tools, and avoid blind sweeps — every "
        "query must test a specific idea.\n"
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
        "ontology_guidance": _ontology_guidance(plan),
    }
    if architecture:
        # Curated platform topology for the components THIS incident implicates:
        # what each does when broken and which dependency to check next — the
        # "thinking material" that used to reach only the playbook renderer.
        stable["platform_architecture"] = architecture
    variable = {
        "my_summary": (result.summary or "")[:1200],
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
    try:
        method(result.agent, result, entity=entity, timestamp=str(getattr(target, "fired_at", "") or ""))
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


def _ontology_guidance(plan: InvestigationPlan | None) -> dict[str, Any]:
    """Bounded, source-scoped TypeDB guidance for one evidence agent.

    The evidence agents receive the runbook as hypotheses and questions, never as
    executable commands. Their domain tool registry remains the enforcement point
    for read-only access.
    """
    directive = plan.diagnostic_directive if plan else {}
    if not isinstance(directive, dict):
        return {}

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
        "probes": [
            item
            for item in (directive.get("probes") or [])
            if isinstance(item, dict)
        ][:4],
        "disconfirm": strings("disconfirm", 4),
        "competing_hypotheses": [
            item
            for item in (directive.get("competing_hypotheses") or [])
            if isinstance(item, dict)
        ][:4],
        "candidate_family": str(directive.get("provisional_family") or ""),
        "collector": str(directive.get("collector") or ""),
        "primary": bool(directive.get("primary")),
        "collector_instruction": str(directive.get("collector_instruction") or ""),
    }
    return {key: value for key, value in guidance.items() if value not in ("", [], None)}


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
    if art.query:
        item["query"] = _compact_value(art.query, limit=300)
    if art.highlights:
        item["highlights"] = art.highlights[:6]
    if art.result is not None:
        item["result"] = _compact_value(art.result, limit=900)
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
        parts.append(_string_leaf_text(art.result))
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
            other != name
            and name.lower() in other.lower()
            and rank_of[other] <= rank_of[name]
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
# agent already queries (known-present in this deployment); Run:ai metricType enums
# are from the Run:ai supported-metrics/telemetry docs, GPU-profiling omitted:
# https://run-ai-docs.nvidia.com/saas/platform-management/monitor-performance/metrics
_KNOWN_PROMQL_SERIES = (
    "runai_queue_allocated_gpus, runai_queue_requested_gpus, "
    "runai_project_allocated_gpus, runai_project_requested_gpus, "
    "kube_pod_status_phase, kube_pod_container_status_restarts_total, "
    "container_memory_working_set_bytes, container_cpu_usage_seconds_total"
)
_RUNAI_METRIC_TYPES = (
    "GPU_UTILIZATION, GPU_MEMORY_USAGE_BYTES, GPU_MEMORY_UTILIZATION, ALLOCATED_GPU, "
    "TOTAL_GPU, CPU_UTILIZATION, CPU_MEMORY_USAGE_BYTES, POD_COUNT, RUNNING_POD_COUNT, "
    "AVG_WORKLOAD_WAIT_TIME, ALLOCATED_GPUS, FREE_GPUS, IDLE_ALLOCATED_GPUS"
)


def _domain_tools(settings: Settings) -> dict[str, dict[str, dict[str, Any]]]:
    """Per-agent tool registries — THE scoping boundary between domains."""
    registry: dict[str, dict[str, dict[str, Any]]] = {
        "kubernetes": {
            "k8s_read": {
                "description": (
                    "Read-only get/list of one Kubernetes kind. args: "
                    f"kind (one of: {', '.join(sorted(_READ_KINDS))}), "
                    "namespace?, name?, label_selector?"
                ),
                "call": _tool_k8s_read,
            },
            "k8s_logs": {
                "description": (
                    "Read a pod's container logs (tail). USE THIS to inspect what a pod "
                    "actually logged. args: pod, namespace, container? (defaults to the "
                    "pod's main container), tail? (line count)"
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
        }
    }
    if settings.enable_pod_exec:
        _allow = "; ".join(" ".join(cmd) for cmd in _EXEC_ALLOWLIST)
        registry["kubernetes"]["k8s_exec"] = {
            "description": (
                "Run ONE read-only inspection command inside a container (no shell, no "
                "writes). args: pod, namespace, command (argv list, EXACTLY one of the "
                f"allowlisted commands), container?. Allowed: {_allow}"
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
                    'args: query (LogQL, e.g. \'{namespace="runai"} |~ "(?i)(error|panic)"\')'
                ),
                "call": _tool_logql,
            }
        }
    if settings.runai_mcp_url:
        registry["runai"] = {
            "runai_api_search": {
                "description": (
                    "Find Run:ai REST API operations by keyword (BM25 over the full "
                    "OpenAPI spec, 426 operations). args: query (keywords, e.g. "
                    "'workload events history')"
                ),
                "call": _tool_runai_search,
            },
            "runai_api_get": {
                "description": (
                    "Call one Run:ai REST API operation — GET ONLY, path must start "
                    "with /api/. args: path (e.g. '/api/v1/workloads'), query? "
                    "(param map, e.g. {'name': 'job-1'}). "
                    f"For metrics endpoints, valid metricType values include: {_RUNAI_METRIC_TYPES}."
                ),
                "call": _tool_runai_get,
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


async def _tool_k8s_logs(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    pod = str(args.get("pod") or args.get("name") or target.pod or "")
    namespace = str(args.get("namespace") or target.namespace or "")
    container = str(args.get("container") or "")
    try:
        tail = int(args.get("tail") or 0)
    except (TypeError, ValueError):
        tail = 0
    item = await k8s_logs(settings, namespace, pod, container=container, tail=tail)
    error = item.get("error")
    lines = item.get("lines") or []
    ns_flag = f" -n {namespace}" if namespace else ""
    c_flag = f" -c {container}" if container else ""
    return {
        "query": f"kubectl logs {pod}{ns_flag}{c_flag}",
        "title": _title(settings, "Pod 로그", "Pod logs"),
        "summary": str(error) if error else f"{len(lines)} log line(s)",
        "error": error,
        "result": item,
        **({"mcp_fallback": item["mcp_fallback"]} if item.get("mcp_fallback") else {}),
    }


async def _tool_k8s_describe(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    kind = str(args.get("kind") or "")
    namespace = str(args.get("namespace") or target.namespace or "")
    name = str(args.get("name") or "")
    item = await k8s_describe(settings, kind, namespace=namespace, name=name)
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
    promql = " ".join(str(args.get("query") or "").split())[:600]
    title = _title(settings, "메트릭 조회 (PromQL)", "Metric query (PromQL)")
    if not promql:
        return {
            "query": "",
            "title": title,
            "summary": "empty PromQL query",
            "error": "empty PromQL query",
        }
    fallback = ""
    if settings.prometheus_mcp_url:
        try:
            item = await prom_mcp_query(settings, "drilldown", promql)
            return {
                "query": promql,
                "title": title,
                "summary": "MCP query_prometheus ok",
                "error": None,
                "result": item,
            }
        except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
            fallback = mcp_fallback_warning(exc)
    else:
        fallback = f"{MCP_FALLBACK_WARNING}: PROMETHEUS_MCP_URL not configured"
    if not settings.prometheus_url:
        return {"query": promql, "title": title, "summary": fallback, "error": fallback}
    item = await prom_query(settings, "drilldown", promql)
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
    logql = " ".join(str(args.get("query") or "").split())[:600]
    title = _title(settings, "로그 조회 (LogQL)", "Log query (LogQL)")
    if not logql:
        return {
            "query": "",
            "title": title,
            "summary": "empty LogQL query",
            "error": "empty LogQL query",
        }
    fallback = ""
    if settings.loki_mcp_url:
        try:
            item = await loki_mcp_query(settings, "drilldown", logql)
            return {
                "query": logql,
                "title": title,
                "summary": f"{item.get('line_count', 0)} MCP log line(s)",
                "error": None,
                "result": item,
            }
        except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
            fallback = mcp_fallback_warning(exc)
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
        },
        headers=headers,
    )
    if response.error or not response.ok:
        error = response.error or f"HTTP {response.status_code}"
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
    result = await mcp_call(settings.postgres_mcp_url, "query", {"sql": sql})
    error = mcp_error(result)
    if error:
        raise RuntimeError(error)
    data = mcp_tool_json(result)
    if isinstance(data, dict) and "raw" in data:
        raise RuntimeError("MCP result was not JSON")
    return [row for row in _postgres_rows(data)[:50] if isinstance(row, dict)]


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
            fallback = mcp_fallback_warning(exc)
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


async def _mcp_call(settings: Settings, tool: str, arguments: dict, url: str = "") -> Any:
    return await mcp_call(url or settings.runai_mcp_url, tool, arguments)


async def _tool_runai_search(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    query = " ".join(str(args.get("query") or "").split())[:200]
    title = _title(settings, "Run:ai API 검색", "Run:ai API spec search")
    if not query:
        return {
            "query": "",
            "title": title,
            "summary": "empty search query",
            "error": "empty search query",
        }
    result = await _mcp_call(settings, "search_runai_api_spec", {"query": query})
    text = _safe_text(_tool_text(result), limit=_RESULT_CHARS)
    if getattr(result, "isError", False):
        error = mcp_error(result)
        return {
            "query": query,
            "title": title,
            "summary": error,
            "error": error,
        }
    return {
        "query": f"search_runai_api_spec {query!r}",
        "title": title,
        "summary": "spec search ok",
        "error": None,
        "result": text,
    }


async def _tool_runai_get(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    path = str(args.get("path") or "").strip()
    title = _title(settings, "Run:ai API 조회 (GET)", "Run:ai API call (GET)")
    # GET-only under /api/ regardless of what the LLM asks for — the drill-down
    # must never mutate Run:ai state or reach non-API routes.
    decoded_path = unquote(path)
    path_parts = decoded_path.split("/")
    raw_path_parts = path.split("/")
    if (
        not path.startswith("/api/")
        or "%" in path
        or len(path_parts) != len(raw_path_parts)
        or any(part in (".", "..") for part in path_parts)
        or any(char in decoded_path for char in ("\\", "?", "#"))
        or any(char.isspace() for char in decoded_path)
    ):
        error = "only GET requests under /api/ are allowed"
        return {"query": path, "title": title, "summary": error, "error": error}
    raw_params = args.get("query") if isinstance(args.get("query"), dict) else {}
    params = {str(k)[:60]: str(v)[:120] for k, v in list(raw_params.items())[:8] if str(k).strip()}
    arguments: dict[str, Any] = {"method": "GET", "path": path[:300]}
    if params:
        arguments["query"] = params
    result = await _mcp_call(settings, "call_runai_api", arguments)
    # The real request an operator could replay with curl.
    query = f"GET {path}" + ("?" + urlencode(params) if params else "")
    if getattr(result, "isError", False):
        error = mcp_error(result)
        return {"query": query, "title": title, "summary": error, "error": error}
    return {
        "query": query,
        "title": title,
        "summary": f"GET {path} ok",
        "error": None,
        "result": _tool_json(result),
    }


def _safe_text(value: str, *, limit: int) -> str:
    text = " ".join(build_masker(()).mask_text(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
