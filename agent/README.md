# Run:AI RCA Agent

FastAPI analysis service for Run:AI RCA.

The service is a component-oriented multi-agent pipeline run by one orchestrator.
Seven evidence collectors gather in parallel, a central investigation loop and
per-collector autonomous drill-down deepen the evidence, then signature matching
(+ BM25 recall), ranking, a skeptical self-check, and synthesis produce one
grounded RCA under an overall deadline. Every LLM stage is optional; with no LLM,
or on any failure, the orchestrator degrades to its deterministic path. See the
**[RCA Pipeline](../docs/RCA-PIPELINE.md)** doc for every stage and the
**[Knowledge Base](../docs/KNOWLEDGE-BASE.md)** doc for the catalogs and ontology
it consults.

Collectors (each owns one domain):

- Run:ai collector — workload/project/queue/quota context (optional runai-mcp sidecar)
- Kubernetes collector — pods/events/nodes, control-plane pod health, read-only pod-exec
- Prometheus collector — queue/project GPU metrics
- Loki collector — workload + `runai`/`runai-backend` control-plane logs
- Postgres collector — RCA-store health (and platform-DB drill-down via `RUNAI_DB_DSN`)
- System collector — node infra (dmesg/journalctl, NVIDIA XID) via a per-node DaemonSet
- Change collector — "what changed?" around the alert window

`configs/runai_rca_engine.yml` is the NeMo Agent Toolkit workflow used as the
in-process orchestration engine. It declares the six RCA pipeline stages as NAT
functions and runs them through the `runai_rca_pipeline` controller.
Pipeline switches: `ENABLE_INVESTIGATION_LOOP`, `ENABLE_AGENT_DRILLDOWN`,
`ANALYSIS_DEADLINE_SECONDS` (default 1500s) — full list in the
[Configuration Reference](../docs/CONFIGURATION.md).

Set `LLM_BASE_URL`, `LLM_MODEL`, and `LLM_API_KEY` to let NAT own the default
LLM transport during analysis. The direct fallback path and `/chat` keep using
the existing HTTP client.

The Python service normally runs analysis through the in-process NAT engine. It
can still run the same pipeline directly for local development and tests; set
`ENABLE_NAT_RUNTIME=false` only when you need to force that path.

When deployed in the same Kubernetes cluster as Run:ai, Prometheus, and Loki,
the collectors query cluster-local service URLs directly. The Helm chart defaults
Prometheus to
`http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090`
and Loki to
`http://loki-read.monitoring.svc.cluster.local:3100`; override those
values when the cluster service names differ. The default uses the direct Loki
query service and avoids gateway-level Basic Auth.

The Loki collector also queries Run:ai control-plane/backend logs with
`RUNAI_LOG_NAMESPACES`, defaulting to `runai,runai-backend`.
Use `KUBERNETES_LIST_LIMIT` and `LOKI_QUERY_LIMIT` to cap evidence volume in
large clusters.
Use `KUBERNETES_NAMESPACES` to restrict direct Kubernetes API collection to a
comma-separated namespace allowlist, and set `KUBERNETES_CLUSTER_SCOPE_ENABLED=false`
when the service account has namespaced RBAC only.

Known troubleshooting cases are loaded from `TROUBLESHOOTING_CASES_FILE`
(`knowledge/troubleshooting_cases.md` by default) and injected into RCA
synthesis. This is static operator memory.

Agent role contracts are loaded from `AGENT_SOULS_FILE`
(`prompts/agent_souls.md` by default). The Run:ai agent is defined as a direct
Run:ai API collector for workload, project, queue, quota, and scheduling
context; it does not run the `runai` CLI by default. Run:ai control-plane pod
and event state belongs to the Kubernetes collector, and `runai` /
`runai-backend` logs belong to the Loki collector.

Similar incident retrieval and feedback learning come from the Backend. The
Backend sends `similar_incidents` and `feedback_hints` in each `/analyze`
request, and synthesis includes those hints in the RCA.
The Analysis Agent owns the final RCA verdict, confidence, impact, missing data,
manual actions, prevention notes, and dashboard summary.
For `/chat`, the Backend also attaches the active incident or alert RCA content
plus `rca_memory`, so the Chat Agent can answer follow-up questions from prior
RCA history instead of behaving like a generic chatbot.

Sensitive values are masked before agent evidence is returned or synthesized.
Built-in redaction is enabled by default and can be extended with
`MASKING_REGEX_LIST_JSON`, a JSON array of regex patterns. Set
`BUILTIN_REDACTION_ENABLED=false` only for controlled debugging, and use
`BUILTIN_REDACTION_HASH_MODE=true` when stable correlation of masked values is
needed without exposing the original secret.

## Run

```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

## Verify

```bash
pytest
python -m compileall app
nat validate --config_file configs/runai_rca_engine.yml
nat run --config_file configs/runai_rca_engine.yml --input '{"alert":{"status":"firing","labels":{"alertname":"RunAIWorkloadPending","namespace":"runai"},"annotations":{"summary":"smoke"},"fingerprint":"fp-smoke"}}'
nat validate --config_file configs/runai_rca_eval.yml
python -m eval.check_nat_eval --min-avg 1.0
python -m eval.run_eval --fixtures eval/fixtures.jsonl --min-top1 0.8
```

Eval has two layers:

- `eval/run_eval.py` measures ranker accuracy over injected collector evidence
  (`fixtures.jsonl`), including Top-1/Top-3 and false-assertion checks.
- `nat eval` through `eval/check_nat_eval.py` runs the real NAT workflow over
  alert text fixtures (`nat_dataset.jsonl`) and gates end-to-end family routing.
  Offline collectors are unavailable by design; only alert-signature routing is
  scored.

Profiler: `configs/runai_rca_engine.yml` includes a commented bottleneck-analysis
example. Enable the same `profiler` block under `eval.general` when running
`nat eval`; NAT writes profiler output under `.tmp/nat/runai_rca_eval`.
