# Configuration Reference

> **Lens:** What's configurable — every setting; the README covers the common path.
> **In this doc:** environment variables · Helm values · behavior notes (pgvector, redaction).

All settings available for Run:AI RCA. README covers the common path; this is the full reference.

## Environment Variables

Backend and agent read these at startup; Helm maps them from the values below.

| Variable | Purpose |
| --- | --- |
| `PORT` | Backend/Agent HTTP port; Helm maps this from the component service port |
| `AGENT_URL` | Backend to Agent URL, default `http://localhost:8000` |
| `KNOWLEDGE_VALIDATOR_URL` | Backend approval-time Agent validator base URL. The backend appends `/knowledge/validate`; Helm defaults this to the in-cluster Agent service. |
| `BACKEND_URL` | Agent to Backend URL used for fire-and-forget analysis progress events. Empty disables progress POSTs; Helm points it at the backend service by default |
| `DYNAMIC_KNOWLEDGE_MODE` | Runtime use of approved incident-derived knowledge: `off`, `shadow` (default), `assist`, or `authoritative`. `shadow` records observations without changing the headline RCA. |
| `RUNTIME_KNOWLEDGE_URL` | Read-only approved-knowledge snapshot URL. When empty, the Agent derives `${BACKEND_URL}/api/v1/knowledge/runtime-snapshot`; Helm exposes an explicit override. |
| `RUNTIME_KNOWLEDGE_TOKEN` | Optional bearer token for the runtime knowledge snapshot endpoint. Empty is safe for the in-cluster default endpoint. |
| `RUNTIME_KNOWLEDGE_REFRESH_SECONDS` | Runtime knowledge refresh interval, default `30` seconds (values below `30` are raised to `30`). |
| `RUNTIME_KNOWLEDGE_TIMEOUT_SECONDS` | Runtime knowledge fetch timeout, default `10` seconds (minimum `1`). |
| `AGENT_REQUEST_TIMEOUT_SECONDS` | Backend timeout for Agent `/analyze` and `/chat` requests, default `1560` (must exceed the agent's `ANALYSIS_DEADLINE_SECONDS`) |
| `MANUAL_AGENT_REQUEST_TIMEOUT_SECONDS` | Backend timeout for operator-triggered Agent `/analyze` requests, default `1560` |
| `TRASH_RETENTION_DAYS` | Backend soft-delete retention before trash incidents are purged, default `30` |
| `SLACK_BOT_TOKEN` | Backend Slack bot token (`xoxb-`, `chat:write` scope, bot invited to the channel). Set together with `SLACK_CHANNEL_ID` to enable incident-analysis notifications. A bot token — not an incoming webhook and not the `xapp-` app token — is required because `chat.postMessage` returns the `ts` used to thread re-analyses. Reinstalling the Slack app invalidates the previous `xoxb-` token. Chart secret key `slackBotToken` |
| `SLACK_CHANNEL_ID` | Channel the backend posts incident-analysis summaries into. Chart secret key `slackChannelId` |
| `SLACK_APP_TOKEN` | Optional app-level token (`xapp-`, `connections:write` scope). Enables the in-message Re-analyze button: clicks arrive over Socket Mode (outbound WebSocket), so no public endpoint is needed. This token is not valid for `chat.postMessage`; keep it separate from `SLACK_BOT_TOKEN`. Requires Socket Mode + Interactivity toggled on in the Slack app settings. Chart secret key `slackAppToken` |
| `DASHBOARD_URL` | Optional external dashboard URL; when set, Slack messages add an "Open Incident" deep-link button (Helm value `backend.env.dashboardUrl`) |
| `LOG_LEVEL` | Agent log level, default `info` |
| `LANGUAGE` | Backend/Agent response language, `en` or `ko` |
| `KUBERNETES_API_URL` | In-cluster Kubernetes API URL, default `https://kubernetes.default.svc` |
| `KUBERNETES_TOKEN_PATH` | Service account token path for in-cluster Kubernetes collection |
| `KUBERNETES_CA_PATH` | Service account CA path for in-cluster Kubernetes collection |
| `KUBERNETES_TIMEOUT_SECONDS` | Kubernetes API request timeout |
| `KUBERNETES_LIST_LIMIT` | Kubernetes pod/event list page size for evidence collection, default `50` |
| `KUBERNETES_NAMESPACES` | Optional comma-separated namespace allowlist for Kubernetes direct collection |
| `KUBERNETES_CLUSTER_SCOPE_ENABLED` | Enables cluster-scoped Kubernetes calls such as node lookups; Helm follows `agent.rbac.clusterWide` |
| `KUBERNETES_MCP_URL` | Kubernetes MCP shared-service URL. When set, Kubernetes collection and drill-down call MCP first and fall back to direct Kubernetes API reads on failure |
| `RUNAI_BASE_URL` | Run:ai control plane URL. No chart default; required as `agent.env.runaiBaseUrl` when `runaiMcp.enabled=true` |
| `RUNAI_BEARER_TOKEN` | Optional Run:ai bearer token secret |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` | Grafana service-account token used by the managed `grafanaMcp` service for Prometheus/Loki datasource read/query access |
| `RUNAI_CLIENT_ID` | Run:ai application client ID |
| `RUNAI_CLIENT_SECRET` | Run:ai application client secret |
| `RUNAI_TOKEN_URL` | Optional OAuth token URL for Run:ai client credentials |
| `RUNAI_WORKLOADS_PATH` | Run:ai workloads API path, default `/api/v1/workloads` |
| `RUNAI_PROJECTS_PATH` | Run:ai projects API path, default `/api/v1/projects` |
| `RUNAI_QUEUES_PATH` | Run:ai queues API path, default `/api/v1/queues` |
| `RUNAI_VERSION_PATH` | Run:ai control-plane version API path, default `/api/v1/version` — enables version-aware suppression of already-fixed known issues |
| `RUNAI_TIMEOUT_SECONDS` | Run:ai API request timeout, default `120` |
| `RUNAI_MCP_URL` | runai-mcp shared service URL (stdio→HTTP bridge, e.g. `http://runai-rca-runai-mcp:8809/mcp`). When set, the runai collector + drill-down reach the 426 Run:ai APIs spec-aware; any failure falls back to the fixed-endpoint collector. Helm runs the ClusterIP service and sets this by default (`runaiMcp.enabled: true`) |
| `RUNAI_LOG_NAMESPACES` | Comma-separated Run:ai control-plane log namespaces, default `runai,runai-backend` |
| `PROMETHEUS_URL` | Prometheus base URL |
| `PROMETHEUS_TIMEOUT_SECONDS` | Prometheus query timeout |
| `PROMETHEUS_MCP_URL` | Grafana MCP URL for Prometheus tools. Helm sets this to the managed `grafanaMcp` ClusterIP service when enabled; fallback uses `PROMETHEUS_URL` |
| `LOKI_URL` | Loki base URL. In Helm this should normally point to the direct read/query service, for example `http://loki-read.monitoring.svc.cluster.local:3100`, not an authenticated gateway. |
| `LOKI_TIMEOUT_SECONDS` | Loki query timeout |
| `LOKI_QUERY_LIMIT` | Maximum log lines requested per Loki query group, default `20` |
| `LOKI_MCP_URL` | Grafana MCP URL for Loki tools. Helm sets this to the same managed `grafanaMcp` ClusterIP service when enabled; fallback uses `LOKI_URL` |
| `ENABLE_SYSTEM_AGENT` | Enable the node-infra System collector (dmesg/journalctl/syslog via a per-node DaemonSet), default `true`; degrades to `unavailable` when `SYSTEM_AGENT_URL` is unset |
| `SYSTEM_AGENT_URL` | Per-node System-agent DaemonSet endpoint (`GET /logs?source=dmesg\|journal\|syslog`) |
| `SYSTEM_AGENT_TOKEN` | Optional bearer token for the System-agent endpoint |
| `SYSTEM_AGENT_TIMEOUT_SECONDS` | System-agent request timeout, default `120` |
| `ENABLE_POD_EXEC` | Allow the Kubernetes collector read-only pod-exec (allowlisted commands: `nvidia-smi`, …), default `true` |
| `POD_EXEC_TIMEOUT_SECONDS` | Pod-exec timeout, default `120` |
| `DATABASE_URL` | Backend Postgres store DSN for incidents, alerts, embeddings, feedback, comments, and analysis runs |
| `DATABASE_CONNECT_TIMEOUT_SECONDS` | Backend Postgres startup connection timeout, default `5` |
| `POSTGRES_DSN` | Agent Postgres diagnostic DSN; defaults to `DATABASE_URL` in Helm |
| `POSTGRES_TIMEOUT_SECONDS` | Agent Postgres diagnostic query timeout |
| `RUNAI_DB_DSN` | Optional read-only DSN for the Run:ai control-plane Postgres. When set, the postgres agent's drill-down can `SELECT` platform data (workloads, audit, clusters, ...) during troubleshooting; single-statement SELECT in a READ ONLY transaction. Provision a read-only DB role. |
| `POSTGRES_MCP_URL` | Postgres MCP shared-service URL. Postgres collection and drill-down call MCP first; fallback uses `RUNAI_DB_DSN` first, then `POSTGRES_DSN` |
| `TROUBLESHOOTING_CASES_FILE` | Local known-cases/playbook markdown path |
| `ARCHITECTURE_FILE` | Run:ai platform topology YAML (components, depends_on, DB schema ownership), default `knowledge/runai_architecture.yaml` — powers playbook check paths and postgres drill-down schema hints |
| `AGENT_SOULS_FILE` | Agent role-contract prompt path, default `prompts/agent_souls.md` |
| `FAMILIES_FILE` | Root-cause family catalog YAML path, default `knowledge/families.yaml`. Load failure falls back to the built-in catalog |
| `COLLECTORS` | Comma-separated collector registry allowlist. Empty/default enables all built-in collectors |
| `EVAL_MIN_TOP1` | Eval gate minimum Top-1 accuracy used by CI/run scripts when no explicit `--min-top1` is passed |
| `MASKING_REGEX_LIST_JSON` | Optional JSON array of custom redaction regexes |
| `BUILTIN_REDACTION_ENABLED` | Enable built-in secret redaction, default `true` |
| `BUILTIN_REDACTION_HASH_MODE` | Replace secrets with stable short hashes instead of `[MASKED]`, default `false` |
| `NVIDIA_API_KEY` | NIM key for NeMo Agent Toolkit workflows |
| `LLM_BASE_URL` | OpenAI-compatible base URL for the NAT-managed default LLM and the operator chat copilot |
| `LLM_MODEL` | OpenAI-compatible model name, for example `auto-router` |
| `LLM_MODEL_PLANNER` / `LLM_MODEL_INVESTIGATION` / `LLM_MODEL_DRILLDOWN` / `LLM_MODEL_SELF_CHECK` / `LLM_MODEL_SYNTHESIS` / `LLM_MODEL_CHAT` / `LLM_MODEL_INSIGHT` / `LLM_MODEL_CRITIC` | Optional stage-specific model overrides. Empty values fall back to `LLM_MODEL` |
| `LLM_API_KEY` | OpenAI-compatible API key secret; enables conversational chat answers when all three LLM vars are set |
| `LLM_REQUEST_TIMEOUT_SECONDS` | LLM request timeout per call (chat and direct fallback reasoning), default `300`, `0` = unlimited |
| `LLM_PRICING_JSON` | Optional JSON map for estimated LLM cost, keyed by model with `prompt_per_mtok` and `completion_per_mtok` values |
| `ENABLE_NAT_RUNTIME` | Run analysis through the in-process NeMo Agent Toolkit engine; default `true` |
| `NAT_CONFIG_FILE` | Internal NeMo engine workflow config path, default `configs/runai_rca_engine.yml` |
| `ENABLE_INVESTIGATION_LOOP` | Central LLM investigation loop: plan → probe the most relevant agents → observe → re-plan, default `false` (Helm sets `true`) |
| `OPEN_WORLD_RCA_MODE` | `off`, `shadow`, `assist`, or `authoritative`; defaults to `shadow`. Shadow records open-world reasoning without changing the RCA headline. |
| `MAX_INVESTIGATION_STEPS` | Legacy compatibility limit; default `0` means semantic completion under the overall analysis deadline. |
| `MAX_REANALYSIS_STEPS` | Legacy compatibility limit for a re-analysis pass; default `0` means semantic completion under the overall analysis deadline. |
| `ENABLE_AGENT_DRILLDOWN` | Per-collector autonomous drill-down: each evidence agent (kubernetes/prometheus/loki/runai) continues through distinct read-only probes until it is done, repeats a query, or reaches the analysis deadline; default `false` (Helm sets `true`) |
| `ANALYSIS_DEADLINE_SECONDS` | Overall hard cap per analysis (graceful degraded report on overrun), default `1500` (25 min), `0` = no cap. Keep the backend `AGENT_REQUEST_TIMEOUT_SECONDS` above this. |
| `ENABLE_RCA_OUTPUT_HARNESS` | Validate the final RCA against live evidence and safety gates, default `true` |
| `MAX_RCA_REPAIR_ATTEMPTS` | Maximum final-report repair passes after harness validation, default `3` |
| `RCA_HARNESS_PASS_SCORE` | Non-fatal harness score threshold (0..100), default `70` |
| `MAX_AUTO_ANALYZE_FANOUT` | Backend: max analyses started per webhook, default `50` |
| `MAX_CONCURRENT_AGENT_RUNS` | Backend: max analyses running against the Agent concurrently, default `50` |
| `FLAPPING_GROUP_WINDOW_MINUTES` | Backend: quiet window before a recurring alert becomes a NEW incident vs another occurrence, code default `120` (Helm sets `360`) |
| `ANALYSIS_BACKFILL_INTERVAL_SECONDS` | Backend: how often to re-drive alerts left without a completed RCA, default `300` (`0` disables) |
| `ANALYSIS_BACKFILL_BATCH` | Backend: alerts re-driven per backfill tick, default `10` |
| `ANALYSIS_BACKFILL_RETRY_COOLDOWN_SECONDS` | Backend: cooldown before retrying a failed alert, default `900` |
| `EMBEDDING_URL` | Backend: OpenAI-compatible `/embeddings` endpoint for similar-incident search. Empty = offline feature-hash fallback (default, lexical) |
| `EMBEDDING_MODEL` | Backend: embedding model name (with `EMBEDDING_URL`) |
| `EMBEDDING_DIM` | Backend: embedding vector dimension, default `384`. Must match the model; changing it requires re-embedding existing rows |
| `EMBEDDING_API_KEY` | Backend: API key for the embedding endpoint (secret key `embeddingApiKey`) |
| `ENABLE_TYPEDB` | Master switch for the TypeDB ontology, default `false` (Helm sets it from `typedb.enabled`, default on). Connection vars below — full detail in [Data Stores](DATABASE.md) |
| `TYPEDB_ADDRESS` | TypeDB server address, default `localhost:1729`; in-cluster `<release>-typedb:1729` |
| `TYPEDB_DATABASE` | TypeDB database name, default `runai_rca` |
| `TYPEDB_USERNAME` / `TYPEDB_PASSWORD` | TypeDB credentials, default `admin` / `password` (CE defaults — override beyond PoC) |
| `TYPEDB_TLS_ENABLED` | Use TLS for the TypeDB connection, default `false` |
| `TYPEDB_TIMEOUT_SECONDS` | TypeDB query timeout, default `60` |

The Helm chart does not expose Loki credential values because the default
deployment is expected to query Loki through the in-cluster read/query service.
If a deployment must call an authenticated external Loki endpoint, inject
`LOKI_BEARER_TOKEN`, `LOKI_BASIC_USERNAME` / `LOKI_BASIC_PASSWORD`, or
`LOKI_TENANT_ID` explicitly with `agent.extraEnv`.

NeMo Agent Toolkit workflow:

- `agent/configs/runai_rca_engine.yml` is the runtime workflow. It declares the
  seven RCA pipeline stages (`enrich`, `plan`, `evidence`, `rank`, `self_check`,
  `synthesize`, and `harness`) as NAT functions and runs them through the in-process
  `runai_rca_pipeline` controller. Provide `LLM_BASE_URL`, `LLM_MODEL`, and
  `LLM_API_KEY` through env or Helm Secret values to let NAT own the default LLM
  transport during analysis.
- `NAT_CONFIG_FILE` is an internal fixed path baked into the agent image.
  Overriding it in deployments is unsupported.

Example Helm override for a LiteLLM/OpenAI-compatible endpoint:

```bash
helm upgrade --install runai-rca charts/runai-rca \
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
| `backend.env.knowledgeValidatorUrl` | Override the approval-time Agent validator base URL; empty uses the in-cluster Agent service and the backend appends `/knowledge/validate` |
| `backend.env.language` / `agent.env.language` | Set RCA language to `en` or `ko` |
| `backend.env.databaseConnectTimeoutSeconds` / `agentRequestTimeoutSeconds` / `manualAgentRequestTimeoutSeconds` | Backend startup DB timeout, automatic/chat Agent timeout, and operator-triggered analysis timeout |
| `secrets.keys.*` | Existing Secret key names for DB, Run:ai, Grafana, NVIDIA, and LLM credentials |
| `secrets.existingSecret` | Existing Secret for Run:ai/NVIDIA/LLM credentials and, by default, DB keys |
| `secrets.databaseExistingSecret` | Existing Secret used only for `DATABASE_URL` / `POSTGRES_DSN` |
| `postgresql.enabled` / `postgresql.auth.*` | Install the bundled Postgres and set its generated DSN user, password, and database |
| `agent.rbac.clusterWide` | Use a ClusterRole for Kubernetes evidence collection; default `true` |
| `agent.rbac.namespaces` | Namespaces that receive Role/RoleBinding when `agent.rbac.clusterWide=false`; defaults to the release namespace |
| `agent.env.kubernetesNamespaces` | Agent-side Kubernetes namespace allowlist; when empty and `clusterWide=false`, Helm derives it from `agent.rbac.namespaces` |
| `agent.env.dynamicKnowledgeMode` / `runtimeKnowledgeUrl` / `runtimeKnowledgeRefreshSeconds` / `runtimeKnowledgeTimeoutSeconds` | Approved runtime-knowledge mode and snapshot client settings. Defaults are `shadow`, the derived backend snapshot URL, `30`, and `10`. |
| `agent.env.runtimeKnowledgeToken` | Optional runtime snapshot bearer token; defaults to empty. Use a secret-managed values mechanism in production. |
| `agent.serviceAccount.annotations` | ServiceAccount annotations for workload identity integrations |
| `{backend,frontend,postgresql}.automountServiceAccountToken` | Disable Kubernetes API token mounts for pods that do not need cluster API access; default `false` |
| `agent.automountServiceAccountToken` | Agent Kubernetes API token mount; default `true` because direct Kubernetes collection uses the service account token |
| `agent.env.runaiBaseUrl` / `agent.env.runaiTokenUrl` | Run:ai API and optional OAuth token endpoint; `agent.env.runaiBaseUrl` has no default and is required when `runaiMcp.enabled=true`; provide `secrets.runaiBearerToken` or client credentials to avoid Run:ai HTTP 401 |
| `agent.env.runaiWorkloadsPath`, `runaiProjectsPath`, `runaiQueuesPath` | Run:ai API path overrides for different Run:ai versions |
| `agent.env.runaiLogNamespaces` | Namespaces for Run:ai control-plane/backend logs, default `runai,runai-backend` |
| `agent.env.prometheusUrl` | In-cluster Prometheus URL, for example `http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090` |
| `agent.env.lokiUrl` | In-cluster Loki query URL, for example `http://loki-read.monitoring.svc.cluster.local:3100`. The chart intentionally avoids the authenticated `loki-gateway` path by default. |
| `grafanaMcp.enabled` / `grafanaMcp.grafanaUrl` / `grafanaMcp.grafanaOrgId` | Run the shared Grafana MCP ClusterIP service for Prometheus/Loki datasource tools, default `true`; the default URL is `http://prometheus-grafana.monitoring.svc.cluster.local:80` and the default org is `1`. The service-account token comes from `GRAFANA_SERVICE_ACCOUNT_TOKEN` in `secrets.existingSecret`; it must be able to list and query both datasources. |
| `kubernetesMcp.enabled` | Run the shared Kubernetes MCP ClusterIP service with its own read-only ServiceAccount/RBAC, default `true`; no `secrets` or `pods/exec` permissions |
| `postgresMcp.enabled` | Run the shared Postgres MCP ClusterIP service backed by the `runai-rca-postgres-mcp` wrapper image, default `true` |
| `agent.env.prometheusMcpUrl` / `agent.env.lokiMcpUrl` / `agent.env.kubernetesMcpUrl` / `agent.env.postgresMcpUrl` | Remote MCP endpoints when not using the managed shared services |
| `agent.env.llmBaseUrl` / `agent.env.llmModel` / `secrets.llmApiKey` | LiteLLM/OpenAI-compatible endpoint, model, and Secret-backed API key for the in-process NAT engine |
| `agent.env.*TimeoutSeconds` | Request/runtime timeouts for Kubernetes, Run:ai, Prometheus, Loki, and Postgres |
| `agent.env.enableRcaOutputHarness` / `maxRcaRepairAttempts` / `rcaHarnessPassScore` | Final RCA harness switch, repair cap, and quality threshold |
| `typedb.ingest.requireApproval` | Ingest only Dashboard-approved incidents (`user_approved_at`), default `true`; `requireReview` is deprecated |
| `typedb.traceV3Backfill.enabled` / `batchSize` / `maxBatches` | Idempotently project approved trace-v3 investigation records into TypeDB. Legacy v1/v2 records are not converted; `maxBatches=0` drains all pages. |
| `typedb.packageMirror.enabled` / `schedule` / `limit` | Advisory mirror of Backend knowledge packages into TypeDB. Default schedule is hourly (`0 * * * *`); Backend remains the approval and activation authority. |
| `agent.env.kubernetesListLimit` / `agent.env.lokiQueryLimit` | Evidence volume controls for Kubernetes list calls and Loki log query groups |
| `agent.env.troubleshootingCasesFile` / `agent.env.agentSoulsFile` | Paths for injected troubleshooting memory and agent role contracts |
| `agent.env.maskingRegexListJson` / `builtinRedaction*` | Cluster-specific secret masking regexes plus built-in redaction enable/hash controls |
| `frontend.config.apiBaseUrl` | Browser API origin when not using the bundled nginx `/api` proxy; leave empty for the default proxy, or use an absolute URL / localhost host:port for an external backend |
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

When `DATABASE_URL` is configured, the backend creates and uses `incidents`,
`alerts`, `incident_embeddings`, `rca_feedback`, `rca_comments`, and
`analysis_runs`. Incidents include `user_approved_at`, `archived_at`, and
`deleted_at` lifecycle columns; analysis runs include `metadata` JSONB for
fields such as `llm_usage`. `context.llm_usage` may include a `nat` subkey with
per-stage token breakdowns (`{stage: {calls, prompt_tokens, completion_tokens,
total_tokens}}`); the top-level keys remain the authoritative totals. Comments
and chat requests that explicitly ask for analysis create
separate analysis runs, so the Analysis Dashboard can track them without
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

Soft-deleted incidents remain queryable through the trash view until
`TRASH_RETENTION_DAYS` elapses. During that period they are excluded from active
incident matching, alert backfill, chat fallback, dashboard alert lists, and
similar-incident memory search. The purge loop runs once on startup and then
hourly.

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
