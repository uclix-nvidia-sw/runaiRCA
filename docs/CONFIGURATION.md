# Configuration Reference

All settings available for Run:AI RCA. README covers the common path; this is the full reference.

## Environment Variables

Backend and agent read these at startup; Helm maps them from the values below.

| Variable | Purpose |
| --- | --- |
| `PORT` | Backend/Agent HTTP port; Helm maps this from the component service port |
| `AGENT_URL` | Backend to Agent URL, default `http://localhost:8000` |
| `AGENT_REQUEST_TIMEOUT_SECONDS` | Backend timeout for Agent `/analyze` and `/chat` requests, default `180` |
| `LOG_LEVEL` | Agent log level, default `info` |
| `LANGUAGE` | Backend/Agent response language, `en` or `ko` |
| `KUBERNETES_API_URL` | In-cluster Kubernetes API URL, default `https://kubernetes.default.svc` |
| `KUBERNETES_TOKEN_PATH` | Service account token path for in-cluster Kubernetes collection |
| `KUBERNETES_CA_PATH` | Service account CA path for in-cluster Kubernetes collection |
| `KUBERNETES_TIMEOUT_SECONDS` | Kubernetes API request timeout |
| `KUBERNETES_LIST_LIMIT` | Kubernetes pod/event list page size for evidence collection, default `50` |
| `KUBERNETES_NAMESPACES` | Optional comma-separated namespace allowlist for Kubernetes direct collection |
| `KUBERNETES_CLUSTER_SCOPE_ENABLED` | Enables cluster-scoped Kubernetes calls such as node lookups; Helm follows `agent.rbac.clusterWide` |
| `RUNAI_BASE_URL` | Run:ai control plane URL |
| `RUNAI_BEARER_TOKEN` | Optional Run:ai bearer token secret |
| `RUNAI_CLIENT_ID` | Run:ai application client ID |
| `RUNAI_CLIENT_SECRET` | Run:ai application client secret |
| `RUNAI_TOKEN_URL` | Optional OAuth token URL for Run:ai client credentials |
| `RUNAI_WORKLOADS_PATH` | Run:ai workloads API path, default `/api/v1/workloads` |
| `RUNAI_PROJECTS_PATH` | Run:ai projects API path, default `/api/v1/projects` |
| `RUNAI_QUEUES_PATH` | Run:ai queues API path, default `/api/v1/queues` |
| `RUNAI_TIMEOUT_SECONDS` | Run:ai API request timeout |
| `RUNAI_LOG_NAMESPACES` | Comma-separated Run:ai control-plane log namespaces, default `runai,runai-backend` |
| `PROMETHEUS_URL` | Prometheus base URL |
| `PROMETHEUS_TIMEOUT_SECONDS` | Prometheus query timeout |
| `PROMETHEUS_MCP_URL` | Optional remote Prometheus MCP URL for the MCP workflow |
| `LOKI_URL` | Loki base URL |
| `LOKI_BEARER_TOKEN` | Optional Loki bearer token secret |
| `LOKI_BASIC_USERNAME` / `LOKI_BASIC_PASSWORD` | Optional Loki basic auth credentials |
| `LOKI_TENANT_ID` | Optional Loki tenant header value sent as `X-Scope-OrgID` |
| `LOKI_TIMEOUT_SECONDS` | Loki query timeout |
| `LOKI_QUERY_LIMIT` | Maximum log lines requested per Loki query group, default `20` |
| `LOKI_MCP_URL` | Optional remote Loki MCP URL for the MCP workflow |
| `DATABASE_URL` | Backend Postgres store DSN for incidents, alerts, embeddings, feedback, comments, and analysis runs |
| `DATABASE_CONNECT_TIMEOUT_SECONDS` | Backend Postgres startup connection timeout, default `5` |
| `POSTGRES_DSN` | Agent Postgres diagnostic DSN; defaults to `DATABASE_URL` in Helm |
| `POSTGRES_TIMEOUT_SECONDS` | Agent Postgres diagnostic query timeout |
| `TROUBLESHOOTING_CASES_FILE` | Local known-cases/playbook markdown path |
| `AGENT_SOULS_FILE` | Agent role-contract prompt path, default `prompts/agent_souls.md` |
| `MASKING_REGEX_LIST_JSON` | Optional JSON array of custom redaction regexes |
| `BUILTIN_REDACTION_ENABLED` | Enable built-in secret redaction, default `true` |
| `BUILTIN_REDACTION_HASH_MODE` | Replace secrets with stable short hashes instead of `[MASKED]`, default `false` |
| `NVIDIA_API_KEY` | NIM key for NeMo Agent Toolkit workflows |
| `LLM_BASE_URL` | LiteLLM/OpenAI-compatible base URL for the LiteLLM NAT workflow |
| `LLM_MODEL` | LiteLLM/OpenAI-compatible model name, for example `auto-router` |
| `LLM_API_KEY` | LiteLLM/OpenAI-compatible API key secret |
| `LLM_REQUEST_TIMEOUT_SECONDS` | LiteLLM request timeout used in the materialized NAT config, default `120` |
| `ENABLE_NAT_RUNTIME` | Run RCA synthesis through the NeMo Agent Toolkit CLI instead of the deterministic in-process fallback, default `false` |
| `NAT_CONFIG_FILE` | Optional NeMo workflow config path, default `configs/runai_rca_workflow.yml` |
| `NAT_TIMEOUT_SECONDS` | NeMo Agent Toolkit CLI execution timeout |
| `VITE_ENABLE_MOCK_DATA` | Frontend local-dev sample data toggle; Helm uses `frontend.config.enableMockData` |

NeMo Agent Toolkit workflows:

- `agent/configs/runai_rca_workflow.yml` runs the component collectors through
  NAT `parallel_executor` and the `analysis_agent` RCA step. It does not require
  external MCP servers.
- `agent/configs/runai_rca_workflow_mcp.yml` adds Prometheus/Loki MCP client
  groups and a NIM-backed Analysis Agent review path for environments where
  those services are available.
- `agent/configs/runai_rca_workflow_litellm.yml` adds a LiteLLM/OpenAI-compatible
  Analysis Agent review path. Set `ENABLE_NAT_RUNTIME=true`, point
  `NAT_CONFIG_FILE` at that config, and provide `LLM_BASE_URL`, `LLM_MODEL`, and
  `LLM_API_KEY` through env or Helm Secret values.

Example Helm override for a LiteLLM/OpenAI-compatible endpoint:

```bash
helm upgrade --install runai-rca charts/runai-rca \
  --set agent.env.enableNatRuntime=true \
  --set agent.env.natConfigFile=/app/configs/runai_rca_workflow_litellm.yml \
  --set-string agent.env.llmBaseUrl=https://litellm.example.com/v1 \
  --set-string agent.env.llmModel=auto-router \
  --set-string secrets.llmApiKey='<llm-api-key>'
```

## Helm Values

Frequently tuned Helm values:

| Value | Purpose |
| --- | --- |
| `nameOverride` / `fullnameOverride` | Override generated Kubernetes resource names when matching existing naming conventions |
| `global.imageRegistry` / `imagePullSecrets` | Private registry prefix and pull secrets applied to all runtime images |
| `{backend,agent,frontend,postgresql}.image.*` | Per-component image repository, tag, and pull policy; empty tags default to the chart app version |
| `{backend,agent,frontend}.replicaCount` | Scale stateless runtime components; keep the bundled Postgres at one replica |
| `{backend,agent,frontend,postgresql}.resources` | CPU/memory requests and limits for production scheduling |
| `backend.env.agentUrl` | Override Backend-to-Agent URL when the Agent is external or remote |
| `backend.env.language` / `agent.env.language` | Set RCA language to `en` or `ko` |
| `backend.env.databaseConnectTimeoutSeconds` / `agentRequestTimeoutSeconds` | Backend startup DB timeout and Backend-to-Agent request timeout |
| `secrets.keys.*` | Existing Secret key names for DB, Run:ai, NVIDIA, and LLM credentials |
| `secrets.existingSecret` | Existing Secret for Run:ai/NVIDIA/LLM credentials and, by default, DB keys |
| `secrets.databaseExistingSecret` | Existing Secret used only for `DATABASE_URL` / `POSTGRES_DSN` |
| `postgresql.enabled` / `postgresql.auth.*` | Install the bundled Postgres and set its generated DSN user, password, and database |
| `agent.rbac.clusterWide` | Use a ClusterRole for Kubernetes evidence collection; default `true` |
| `agent.rbac.namespaces` | Namespaces that receive Role/RoleBinding when `agent.rbac.clusterWide=false`; defaults to the release namespace |
| `agent.env.kubernetesNamespaces` | Agent-side Kubernetes namespace allowlist; when empty and `clusterWide=false`, Helm derives it from `agent.rbac.namespaces` |
| `agent.serviceAccount.annotations` | ServiceAccount annotations for workload identity integrations |
| `{backend,frontend,postgresql}.automountServiceAccountToken` | Disable Kubernetes API token mounts for pods that do not need cluster API access; default `false` |
| `agent.automountServiceAccountToken` | Agent Kubernetes API token mount; default `true` because direct Kubernetes collection uses the service account token |
| `agent.env.runaiBaseUrl` / `agent.env.runaiTokenUrl` | Run:ai API and optional OAuth token endpoint; provide `secrets.runaiBearerToken` or client credentials to avoid Run:ai HTTP 401 |
| `agent.env.runaiWorkloadsPath`, `runaiProjectsPath`, `runaiQueuesPath` | Run:ai API path overrides for different Run:ai versions |
| `agent.env.runaiLogNamespaces` | Namespaces for Run:ai control-plane/backend logs, default `runai,runai-backend` |
| `agent.env.prometheusUrl` | In-cluster Prometheus URL, for example `http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090` |
| `agent.env.lokiUrl` / `agent.env.lokiTenantId` | In-cluster Loki URL and optional `X-Scope-OrgID` tenant header, for example `http://loki-gateway.monitoring.svc.cluster.local` |
| `secrets.lokiBearerToken` / `secrets.lokiBasicUsername` / `secrets.lokiBasicPassword` | Optional Loki auth credentials; bearer auth takes precedence over basic auth |
| `agent.env.prometheusMcpUrl` / `agent.env.lokiMcpUrl` | Remote MCP endpoints when using the MCP workflow |
| `agent.env.llmBaseUrl` / `agent.env.llmModel` / `secrets.llmApiKey` | LiteLLM/OpenAI-compatible endpoint, model, and Secret-backed API key for `runai_rca_workflow_litellm.yml` |
| `agent.env.*TimeoutSeconds` | Request/runtime timeouts for Kubernetes, Run:ai, Prometheus, Loki, Postgres, and NAT |
| `agent.env.kubernetesListLimit` / `agent.env.lokiQueryLimit` | Evidence volume controls for Kubernetes list calls and Loki log query groups |
| `agent.env.troubleshootingCasesFile` / `agent.env.agentSoulsFile` | Paths for injected troubleshooting memory and agent role contracts |
| `agent.env.maskingRegexListJson` / `builtinRedaction*` | Cluster-specific secret masking regexes plus built-in redaction enable/hash controls |
| `frontend.config.apiBaseUrl` | Browser API base URL when not using the bundled nginx `/api` proxy; accepts absolute URLs, `/api`-style paths, or localhost host:port values |
| `frontend.config.enableMockData` | Show sample dashboard records when no live incidents or alerts exist, or when the local dev backend is unavailable; default `false` in Helm |
| `frontend.nginx.*` | Frontend nginx proxy timeout and body-size controls for REST, webhook, and SSE traffic; defaults keep event streams open for one hour |
| `backend.extraEnv`, `agent.extraEnv`, `frontend.extraEnv` | Additional container env entries for deployment-specific settings |
| `podAnnotations` / `podLabels` | Global pod metadata applied to Backend, Agent, Frontend, and bundled Postgres |
| `{backend,agent,frontend,postgresql}.podAnnotations` / `.podLabels` | Component-specific pod metadata merged over global metadata |
| `podSecurityContext` / `securityContext` | Global pod and container security contexts |
| `{backend,agent,frontend,postgresql}.podSecurityContext` / `.securityContext` | Component-specific pod and container security contexts |
| `priorityClassName` / `topologySpreadConstraints` / `nodeSelector` / `affinity` / `tolerations` | Global scheduling policy for all pods |
| `{backend,agent,frontend,postgresql}.priorityClassName` / `.topologySpreadConstraints` | Component-specific priority and spread scheduling overrides |
| `{backend,agent,frontend,postgresql}.nodeSelector` / `.affinity` / `.tolerations` | Component-specific node placement overrides; fall back to the global scheduling values |
| `{backend,agent,frontend}.service.type` / `.port` | Service exposure type and port for each runtime component |
| `{backend,agent,frontend,postgresql}.service.annotations` | Service annotations for cloud/load-balancer or mesh integrations |
| `ingress.*` | Optional Ingress host, path, class, annotations, and TLS settings for the frontend service |
| `{backend,agent,frontend}.readinessProbe` / `.livenessProbe` | HTTP probe overrides for each service |
| `postgresql.readinessProbe` / `postgresql.livenessProbe` | Bundled Postgres probe overrides; empty values use a `pg_isready` default based on `postgresql.auth.username` |
| `postgresql.persistence.*` | PVC enablement, storage class, and size for bundled Postgres |

## Behavior Notes


For annotation keys that contain dots or slashes, prefer a small values file. If
you use `--set`, escape dots and use `--set-string`, for example:

```bash
helm upgrade --install runai-rca charts/runai-rca \
  --set-string 'backend.service.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-type=nlb'
```

Mock data is a frontend-only sample mode. It is enabled by default during Vite
local development, disabled by default in Helm/static deployments, and is shown
after the Backend returns empty incident, alert, and analysis-run lists, or when
the local dev Backend is unavailable. As soon as real incident, alert, or
analysis-run data is returned by the Backend, the UI uses the live values and
does not mix mock records into Operations, Analysis, Evidence, or Agents.

When `DATABASE_URL` is configured, the backend creates and uses `incidents`,
`alerts`, `incident_embeddings`, `rca_feedback`, `rca_comments`, and
`analysis_runs`. Comments and chat requests that explicitly ask for analysis
create separate analysis runs, so the Analysis Dashboard can track them without
overwriting the original RCA. On startup it logs `pgvector=enabled` when
`CREATE EXTENSION vector` succeeds, then adds a dense `embedding vector(384)`
column and an HNSW cosine index to `incident_embeddings`. Dense vectors are
derived deterministically from incident text with signed feature hashing (no
embedding model dependency, so the backend stays self-contained next to the
agent), and free-text memory search runs in Postgres via the pgvector `<=>`
cosine operator. If the pgvector extension is not available, the backend still
stores sparse text vectors in JSONB and serves similar-incident search with
in-process cosine similarity. When `POSTGRES_DSN` is configured, the Postgres
agent checks connectivity, active connections, long-running transactions,
pgvector availability, and expected RCA table presence. If it is not configured,
the agent marks Postgres evidence as unavailable without blocking the rest of the
RCA.

No separate migration command is required for these RCA tables on a fresh
database: backend startup uses idempotent `CREATE TABLE IF NOT EXISTS`,
`CREATE INDEX IF NOT EXISTS`, and `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
statements. External Postgres still needs the database/user to exist and the
user to have schema/table create and read/write privileges.

Sensitive values are redacted before evidence is returned to the backend or
passed into NeMo synthesis. The built-in redactor masks common secret keys,
Authorization headers, JWT-like values, token query parameters, Postgres URL
passwords, long base64 blobs, Kubernetes env values, command flags, sensitive
annotation keys, and embedded annotation secrets. Add cluster-specific patterns
with `MASKING_REGEX_LIST_JSON` when needed.
