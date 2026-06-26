# Run:AI RCA Agent

FastAPI analysis service for Run:AI RCA.

The service is structured around component collectors that map directly to the
planned multi-agent topology:

- Run:ai collector
- Kubernetes collector
- Prometheus collector
- Loki collector
- Postgres collector
- Analysis Agent

`configs/runai_rca_workflow.yml` is the default NeMo Agent Toolkit workflow used
as the orchestration backbone. It runs the Run:ai, Kubernetes, Postgres,
Prometheus, and Loki collectors in parallel, then invokes `analysis_agent` to
produce the KubeRCA-style RCA shown in the Analysis Dashboard.

`configs/runai_rca_workflow_mcp.yml` is the MCP/LLM variant. Use it when
Prometheus/Loki MCP servers and NVIDIA NIM credentials are available.
By default it points at local MCP endpoints; set `PROMETHEUS_MCP_URL` and
`LOKI_MCP_URL` to use remote MCP servers without editing the workflow file.

The Python service can run in deterministic fallback mode for local development
and tests. Set `ENABLE_NAT_RUNTIME=true` to delegate analysis to the `nat` CLI.

When deployed in the same Kubernetes cluster as Run:ai, Prometheus, and Loki,
the collectors query cluster-local service URLs directly. The Helm chart defaults
Prometheus to
`http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090`
and Loki to `http://loki-gateway.monitoring.svc.cluster.local`; override those
values when the cluster service names differ.

The Loki collector also queries Run:ai control-plane/backend logs with
`RUNAI_LOG_NAMESPACES`, defaulting to `runai,runai-backend`.

Known troubleshooting cases are loaded from `TROUBLESHOOTING_CASES_FILE`
(`knowledge/troubleshooting_cases.md` by default) and injected into fallback and
NeMo synthesis. This is static operator memory.

Agent role contracts are loaded from `AGENT_SOULS_FILE`
(`prompts/agent_souls.md` by default). The Run:ai agent is defined as a direct
Run:ai API collector for workload, project, queue, quota, and scheduling
context; it does not run the `runai` CLI by default. Run:ai control-plane pod
and event state belongs to the Kubernetes collector, and `runai` /
`runai-backend` logs belong to the Loki collector.

Similar incident retrieval and feedback learning come from the Backend. The
Backend sends `similar_incidents` and `feedback_hints` in each `/analyze`
request, and the fallback/NeMo synthesis paths include those hints in the RCA.
The Analysis Agent owns the final RCA verdict, confidence, impact, missing data,
manual actions, prevention notes, and dashboard summary.
For `/chat`, the Backend also attaches the active incident or alert RCA content
plus `rca_memory`, so the Chat Agent can answer follow-up questions from prior
RCA history instead of behaving like a generic chatbot.

Sensitive values are masked before agent evidence is returned or synthesized.
Built-in redaction is enabled by default and can be extended with
`MASKING_REGEX_LIST_JSON`, a JSON array of regex patterns.

## Run

```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

## Verify

```bash
pytest
python -m compileall app
nat validate --config_file configs/runai_rca_workflow.yml
```
