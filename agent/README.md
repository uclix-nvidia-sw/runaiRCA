# Run:AI RCA Agent

FastAPI analysis service for Run:AI RCA.

The service is structured around component collectors that map directly to the
planned multi-agent topology:

- Run:ai collector
- Kubernetes collector
- Prometheus collector
- Loki collector
- Postgres collector
- Synthesis step

`configs/runai_rca_workflow.yml` is the default NeMo Agent Toolkit workflow used
as the orchestration backbone. It runs the Run:ai, Kubernetes, Postgres,
Prometheus, and Loki collectors in parallel and synthesizes a KubeRCA-style RCA.

`configs/runai_rca_workflow_mcp.yml` is the MCP/LLM variant. Use it when
Prometheus/Loki MCP servers and NVIDIA NIM credentials are available.

The Python service can run in deterministic fallback mode for local development
and tests. Set `ENABLE_NAT_RUNTIME=true` to delegate analysis to the `nat` CLI.

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
