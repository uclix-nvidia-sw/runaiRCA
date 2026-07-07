"""Per-collector autonomous drill-down loops (LLM-gated, read-only).

Each evidence agent (kubernetes / prometheus / loki / runai) runs its OWN small
bounded LLM loop after the base gather: it looks at ITS OWN evidence and decides
follow-up read-only queries in ITS OWN domain. Tool scoping is structural — each
loop receives only its domain's tool registry, so the kubernetes loop cannot
call the Run:ai API and vice versa. Follow-up results are appended to the
collector's artifacts, where the existing pipeline (masking, signature matching,
the verify pass, synthesis) consumes them with zero changes.

Best-effort like the central investigation loop: flag off (ENABLE_AGENT_DRILLDOWN),
no LLM, or ANY failure -> the base evidence stands. Read-only by construction:
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

from app.collectors.base import (
    AnalysisTarget,
    CollectorResult,
    artifact,
    salient_markers,
    signals_line,
)
from app.collectors.http_json import get_json
from app.collectors.kubernetes import (
    _READ_KINDS,
    k8s_read,
    kind_lookup_title,
    kubectl_repr,
)
from app.collectors.loki import _loki_headers, _loki_streams, _sample_lines, loki_mcp_query
from app.collectors.prometheus import prom_mcp_query, prom_query
from app.collectors.runai_mcp import _tool_json, _tool_text
from app.config import Settings
from app.llm import complete_json, llm_configured, token_budget_exceeded, token_budget_warning
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
)
from app.plan import InvestigationPlan

_log = logging.getLogger(__name__)

_MAX_QUERIES_PER_STEP = 3
_RESULT_CHARS = 1500  # per-query result excerpt fed back into the loop
_USER_PROMPT_CHARS = 6000


async def run_drilldowns(
    settings: Settings,
    results: list[CollectorResult],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
) -> None:
    """Run every domain's drill-down loop concurrently. Never raises."""
    if not settings.enable_agent_drilldown or not llm_configured(
        settings, settings.llm_model_drilldown
    ):
        return
    registry = _domain_tools(settings)
    tasks = [
        _drill_one(settings, result, registry[result.agent], target, plan)
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
) -> None:
    """One agent's bounded think->query->observe loop over its own evidence."""
    try:
        architecture = _implicated_architecture(settings, result, target)
        history: list[dict[str, Any]] = []
        for step in range(max(1, settings.drilldown_max_steps)):
            if token_budget_exceeded(settings):
                result.warnings.append(token_budget_warning(settings))
                break
            decision = await complete_json(
                settings,
                system=_system_prompt(result.agent, tools),
                user=_user_prompt(result, target, plan, history, architecture),
                model=settings.llm_model_drilldown,
            )
            if decision is None:
                # An LLM transport/parse failure must be distinguishable from a
                # legitimate "done" — otherwise a dead LLM looks like a satisfied
                # agent and nobody notices drill-down never ran (the litellm
                # provider incident). Surface it in the report warnings.
                result.warnings.append(
                    f"{result.agent} drill-down stopped at step {step + 1}: "
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
            queries = [
                q
                for q in (decision.get("queries") or [])
                if isinstance(q, dict) and str(q.get("tool") or "") in tools
            ][:_MAX_QUERIES_PER_STEP]
            if not queries:
                break
            _log.info(
                "drilldown %s: step %d running %d quer(ies)",
                result.agent,
                step + 1,
                len(queries),
            )
            for q in queries:
                name = str(q.get("tool"))
                args = q.get("args") if isinstance(q.get("args"), dict) else {}
                outcome = await _call_tool_safely(tools[name]["call"], settings, target, args)
                history.append(
                    {
                        "tool": name,
                        "args": json.dumps(args, default=str)[:300],
                        "outcome": json.dumps(outcome, default=str)[:_RESULT_CHARS],
                    }
                )
                # Finding-first: surface the problem signals in the data and hand
                # them to the UI as highlights; the raw result stays attached.
                markers = salient_markers(outcome.get("result"))
                summary = str(outcome.get("summary") or outcome.get("error") or name)
                if markers:
                    summary = (
                        f"{summary} — {signals_line(markers, getattr(settings, 'language', 'en'))}"
                    )
                result.artifacts.append(
                    artifact(
                        agent=result.agent,
                        source=result.agent,
                        type="drilldown_query",
                        status="unavailable" if outcome.get("error") else "ok",
                        confidence="medium",
                        query=str(outcome.get("query") or name),
                        title=outcome.get("title"),
                        highlights=markers or None,
                        summary=summary,
                        result=outcome.get("result"),
                    )
                )
    except Exception:  # noqa: BLE001 - drill-down is best-effort; base evidence stands
        _log.debug("drill-down for %s aborted", result.agent, exc_info=True)


async def _call_tool_safely(
    call: Any, settings: Settings, target: AnalysisTarget, args: dict
) -> dict:
    try:
        outcome = await call(settings, target, args)
        return outcome if isinstance(outcome, dict) else {"error": "tool returned no result"}
    except Exception as exc:  # noqa: BLE001 - a failing query is an observation
        return {"error": f"{exc.__class__.__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Prompts


def _system_prompt(agent: str, tools: dict[str, dict[str, Any]]) -> str:
    tool_lines = "\n".join(f"- {name}: {spec['description']}" for name, spec in tools.items())
    return (
        f"You are the {agent} evidence agent for a Run:ai GPU-platform RCA, autonomously "
        "drilling deeper into YOUR domain only. Look at your evidence so far and decide "
        "whether one more round of READ-ONLY follow-up queries would materially confirm or "
        "refute the investigation's hypotheses. Fetch data RELATED to the incident — the "
        "workload's controller, its project/queue, the Run:ai control-plane component "
        "involved, correlated namespaces and time windows — never your own datasource's "
        "health (the base collector already covered that). Prefer narrowing: one pod, one "
        "namespace, one resource, a tighter filter. Conclude (action=done) as soon as the "
        "evidence is sufficient — never query for completeness.\n"
        f"Tools available to you (your only tools; there are no others):\n{tool_lines}\n"
        'Respond with ONLY JSON: {"action":"query"|"done","reason":str,'
        '"queries":[{"tool":str,"args":{...}}]} with at most '
        f"{_MAX_QUERIES_PER_STEP} queries per step."
    )


def _user_prompt(
    result: CollectorResult,
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    history: list[dict[str, Any]],
    architecture: list[str] | None = None,
) -> str:
    plan_dict = plan.as_dict() if plan else {}
    payload = {
        "target": {
            key: getattr(target, key, "")
            for key in ("namespace", "workload_name", "pod", "node", "project")
        },
        "plan_focus": plan_dict.get("focus"),
        "hypotheses": (plan_dict.get("hypotheses") or [])[:4],
        "my_summary": (result.summary or "")[:1200],
        "my_artifacts": [
            {"type": art.type, "summary": (art.summary or "")[:300]}
            for art in result.artifacts[-8:]
        ],
        "drilldown_so_far": history[-8:],
    }
    if architecture:
        # Curated platform topology for the components THIS incident implicates:
        # what each does when broken and which dependency to check next — the
        # "thinking material" that used to reach only the playbook renderer.
        payload["platform_architecture"] = architecture
    return json.dumps(payload, default=str, ensure_ascii=False)[:_USER_PROMPT_CHARS]


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
        [result.summary or "", *(art.summary or "" for art in result.artifacts[-8:])]
    ).lower()
    ranked: list[tuple[int, int, str]] = []
    for name in components:
        lowered = name.lower()
        if lowered in target_text:
            ranked.append((0, -len(name), name))
        elif lowered in evidence_text:
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


# ---------------------------------------------------------------------------
# Domain tools. Each: async (settings, target, args) -> {query, summary, error?, result?}


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
            }
        }
    }
    if settings.prometheus_mcp_url or settings.prometheus_url:
        registry["prometheus"] = {
            "promql_query": {
                "description": (
                    "One MCP-first PromQL instant query against cluster metrics. args: "
                    "query (PromQL, e.g. 'rate(kube_pod_container_status_restarts_"
                    'total{namespace="x"}[15m])\')'
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
                    "(param map, e.g. {'name': 'job-1'})"
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
    if item.get("mcp_fallback"):
        summary = f"{item['mcp_fallback']}; {summary}"
    return {
        # The real command an operator would have typed, not a param dump.
        "query": kubectl_repr(kind, namespace=namespace, name=name, label_selector=label_selector),
        "title": kind_lookup_title(kind, getattr(settings, "language", "en")),
        "summary": summary,
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
    if fallback:
        summary = f"{fallback}; {summary}"
    return {
        "query": promql,
        "title": title,
        "summary": summary,
        "error": error,
        "result": item,
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
        if fallback:
            error = f"{fallback}; {error}"
        return {"query": logql, "title": title, "summary": error, "error": error}
    lines = _sample_lines(_loki_streams(response.data), limit=10)
    summary = f"{len(lines)} sample log line(s)" if lines else "no matching log lines"
    if fallback:
        summary = f"{fallback}; {summary}"
    return {
        "query": logql,
        "title": title,
        "summary": summary,
        "error": None,
        "result": {"lines": lines},
    }


# --- read-only SQL (postgres agent) ----------------------------------------

_SQL_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|vacuum|"
    r"call|do|execute|set|listen|notify|lock|reindex|refresh|prepare|deallocate|merge)\b",
    re.IGNORECASE,
)


def _validate_select(sql: str) -> tuple[str | None, str]:
    """(error, normalized_sql). Fail-closed: single statement, SELECT/WITH only."""
    text = " ".join((sql or "").split()).strip().rstrip(";").strip()
    if not text:
        return "empty SQL query", text
    if ";" in text:
        return "a single SQL statement is required", text
    if not re.match(r"(?i)^(select|with)\b", text):
        return "only SELECT/WITH queries are allowed", text
    match = _SQL_FORBIDDEN.search(text)
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
    if not re.search(r"(?i)\blimit\s+\d", sql):
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
    summary = f"{len(rows)} row(s)"
    if fallback:
        summary = f"{fallback}; {summary}"
    return {
        "query": sql,
        "title": title,
        "summary": summary,
        "error": None,
        "result": {"rows": rows},
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
    text = _tool_text(result)[:_RESULT_CHARS]
    if getattr(result, "isError", False):
        return {
            "query": query,
            "title": title,
            "summary": text or "tool error",
            "error": text or "tool error",
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
    if not path.startswith("/api/"):
        error = "only GET requests under /api/ are allowed"
        return {"query": path, "title": title, "summary": error, "error": error}
    raw_params = args.get("query") if isinstance(args.get("query"), dict) else {}
    params = {str(k)[:60]: str(v)[:120] for k, v in list(raw_params.items())[:8] if str(k).strip()}
    arguments: dict[str, Any] = {"method": "GET", "path": path[:300]}
    if params:
        arguments["query"] = params
    result = await _mcp_call(settings, "call_runai_api", arguments)
    # The real request an operator could replay with curl.
    query = f"GET {path}" + (
        "?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else ""
    )
    if getattr(result, "isError", False):
        error = _tool_text(result)[:300] or "tool error"
        return {"query": query, "title": title, "summary": error, "error": error}
    return {
        "query": query,
        "title": title,
        "summary": f"GET {path} ok",
        "error": None,
        "result": _tool_json(result),
    }
