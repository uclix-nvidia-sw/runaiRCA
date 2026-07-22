from __future__ import annotations

from dataclasses import replace

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.services.query_memory import QueryMemory, domain_query_key


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="cluster-a",
        project="project-a",
        queue="queue-a",
        namespace="team-a",
        workload_name="trainer",
        workload_type="Job",
        runai_workload_id="7c0cce74-6f77-4264-9df7-d9fd606a6f47",
        node="gpu-01",
        pod="trainer-0",
        severity="warning",
        alert_name="PodFailure",
        fired_at="2026-07-22T01:00:00Z",
        resolved_at="2026-07-22T01:10:00Z",
    )


def test_query_memory_blocks_success_and_bounds_failed_retry() -> None:
    memory = QueryMemory()

    assert memory.claim("same-query")
    assert not memory.claim("same-query")
    memory.complete("same-query", succeeded=False)
    assert memory.claim("same-query")
    memory.complete("same-query", succeeded=False)
    assert not memory.claim("same-query")

    assert memory.claim("successful-query")
    memory.complete("successful-query", succeeded=True)
    assert not memory.claim("successful-query")


def test_domain_query_identity_normalizes_cross_path_aliases() -> None:
    target = _target()

    named_pod_read = domain_query_key(
        "kubernetes",
        {
            "tool": "k8s_read",
            "args": {"kind": "pod", "namespace": "team-a", "name": "trainer-0"},
        },
        target,
    )
    pod_describe = domain_query_key(
        "kubernetes",
        {
            "tool": "k8s_describe",
            "args": {"kind": "pods", "namespace": "team-a", "name": "trainer-0"},
        },
        target,
    )
    assert named_pod_read == pod_describe

    k8s_change = domain_query_key(
        "kubernetes",
        {"tool": "k8s_change_timeline", "args": {"source": "events"}},
        target,
    )
    change_agent = domain_query_key(
        "change",
        {"tool": "change_query", "args": {"kind": "event"}},
        target,
    )
    assert k8s_change == change_agent

    sql_select = domain_query_key(
        "postgres", {"tool": "sql_select", "args": {"query": "SELECT  id  FROM jobs"}}, target
    )
    sql_query = domain_query_key(
        "postgres", {"tool": "sql_query", "args": {"sql": "SELECT id FROM jobs"}}, target
    )
    assert sql_select == sql_query

    escaped_logql = domain_query_key(
        "loki",
        {"tool": "logql_query", "args": {"query": r'{namespace=\"team-a\"}'}},
        target,
    )
    normalized_logql = domain_query_key(
        "loki",
        {"tool": "logql_query", "args": {"query": '{namespace="team-a"}'}},
        target,
    )
    assert escaped_logql == normalized_logql


def test_domain_query_identity_keeps_target_and_window_distinct() -> None:
    target = _target()
    query = {"tool": "promql_query", "args": {"query": "up"}}

    original = domain_query_key("prometheus", query, target)
    another_node = domain_query_key("prometheus", query, replace(target, node="gpu-02"))
    another_window = domain_query_key(
        "prometheus", query, replace(target, fired_at="2026-07-22T02:00:00Z")
    )

    assert original != another_node
    assert original != another_window


def test_seed_results_recovers_successful_queries_for_every_evidence_domain() -> None:
    target = _target()
    results = [
        CollectorResult(
            agent="prometheus",
            status="partial",
            summary="one query succeeded",
            details={
                "queries": [
                    {"query": "up", "status_code": 200},
                    {"query": "bad_metric", "status_code": 500, "error": "failed"},
                ]
            },
        ),
        CollectorResult(
            agent="loki",
            status="ok",
            summary="logs read",
            details={"queries": [{"query": '{namespace="team-a"}', "status_code": 200}]},
        ),
        CollectorResult(
            agent="runai",
            status="partial",
            summary="official MCP partial",
            details={
                "queries": [
                    {"name": "workload_status", "status_code": 200},
                    {"name": "project_resources", "error": "denied", "status_code": 403},
                ]
            },
        ),
        CollectorResult(
            agent="system",
            status="partial",
            summary="journal succeeded",
            details={
                "node": "gpu-01",
                "sources": [
                    {"source": "journal", "status_code": 200},
                    {"source": "dmesg", "status_code": 500, "error": "failed"},
                ],
            },
        ),
        CollectorResult(
            agent="postgres",
            status="ok",
            summary="query succeeded",
            artifacts=[
                artifact(
                    agent="postgres",
                    source="postgres",
                    type="drilldown_query",
                    status="ok",
                    confidence="medium",
                    query="SELECT id FROM jobs",
                    summary="one row",
                    result={"rows": [{"id": 1}]},
                )
            ],
        ),
    ]
    memory = QueryMemory()
    memory.seed_results(results, target)

    assert memory.contains(
        domain_query_key("prometheus", {"tool": "promql_query", "args": {"query": "up"}}, target)
    )
    assert not memory.contains(
        domain_query_key(
            "prometheus", {"tool": "promql_query", "args": {"query": "bad_metric"}}, target
        )
    )
    assert memory.contains(
        domain_query_key(
            "loki",
            {"tool": "logql_query", "args": {"query": '{namespace="team-a"}'}},
            target,
        )
    )
    assert memory.contains(
        domain_query_key("runai", {"tool": "runai_workload_status", "args": {}}, target)
    )
    assert not memory.contains(
        domain_query_key("runai", {"tool": "runai_project_resources", "args": {}}, target)
    )
    assert memory.contains(
        domain_query_key(
            "system", {"tool": "system_log_query", "args": {"source": "journal"}}, target
        )
    )
    assert not memory.contains(
        domain_query_key(
            "system", {"tool": "system_log_query", "args": {"source": "dmesg"}}, target
        )
    )
    assert memory.contains(
        domain_query_key(
            "postgres", {"tool": "sql_select", "args": {"query": "SELECT id FROM jobs"}}, target
        )
    )
