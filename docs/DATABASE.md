# Data Stores

> **Lens:** How it's built (data) — the two stores and what each owns.
> **In this doc:** PostgreSQL tables · TypeDB ontology · ingestion paths · connection config.

Run:AI RCA uses two stores with distinct roles. See [Architecture](ARCHITECTURE.md) for the
runtime flow; this document is the data-structure reference.

| Store | Role | Owner | Required? |
|---|---|---|---|
| **PostgreSQL** | Operational source of truth: incidents, alerts, RCA results, operator feedback, similarity vectors | Go backend | Yes (in-memory fallback for local dev) |
| **TypeDB** | Ontology knowledge graph: typed entities + relations for relational reasoning at synthesis | Agent | No (`typedb.enabled`, default on in Helm) |

The graph is **derived from** Postgres — a review-gated projection, not a second
source of truth.

```mermaid
flowchart LR
  BE[Backend] <-->|"read/write · pgvector similarity"| PG[(PostgreSQL + pgvector)]
  PG -.->|review-gated ingestion| TDB[(TypeDB ontology)]
  BE -->|similar_incidents + feedback_hints| AG[Agent orchestrator]
  AG -->|"enrich / graph_remediation"| TDB
```

**pgvector** similarity is owned by the **backend** (Go), not the agent: the
backend runs the cosine search and passes the matches into each `/analyze`
request. The agent **orchestrator** owns the **TypeDB** side — it consults the
graph during analysis. See [RCA Pipeline](RCA-PIPELINE.md) and
[Knowledge Base](KNOWLEDGE-BASE.md).

---

## 1. PostgreSQL (operational)

Tables are auto-created by the backend on startup (`backend/store_postgres.go`).

| Table | Purpose | Key columns |
|---|---|---|
| `incidents` | Correlated alert groups | `incident_id` (PK), `correlation_key`, `title`, `severity`, `status`, `fired_at`, `resolved_at`, `alert_count` |
| `alerts` | Individual alerts + their RCA | `alert_id` (PK), `incident_id` (FK), `fingerprint`, `occurrence_count`, `occurrence_pods` (JSONB), `labels`/`annotations` (JSONB), `analysis_summary`/`analysis_detail`, `analysis_quality`, `capabilities`/`missing_data`/`warnings`/`artifacts` (JSONB) |
| `incident_embeddings` | Similarity memory | `incident_id` (PK), `alert_id`, `analysis_summary`/`analysis_detail`, `labels` (JSONB), `vector_json` (JSONB), `embedding vector(384)` + HNSW cosine index |
| `rca_feedback` | Operator votes | `feedback_id` (PK), `target_type`, `target_id`, `vote` (`up`/`down`), `author`, `created_at` |
| `rca_comments` | Operator notes | `comment_id` (PK), `target_type`, `target_id`, `body`, `author`, `created_at` |
| `analysis_runs` | RCA execution history | `run_id` (PK), `source` (`auto`/`manual`/`chat`/`feedback`), `status`, `target_type`, `target_id`, `analysis_*`, `created_at` |

**Similarity search**: `incident_embeddings.embedding` (pgvector, HNSW cosine) is
the primary path; a JSONB sparse-vector cosine fallback runs when pgvector is
unavailable. The 384-dim vector is a deterministic feature-hash of the RCA text
(no model dependency) — see `backend/memory.go`. `labels`/`annotations` JSONB are
the richest entity source consumed by ingestion (cluster/node/queue/etc.).

---

## 2. TypeDB (ontology knowledge graph)

Schema: `agent/ontology/schema.tql` (TypeQL 3.x). Three layers.

### Infra layer — *populated by ingestion*
`cluster`, `node`, `namespace`, `project`, `queue`, `workload`, `pod`,
`control_plane_component`.
GPU is modeled as attributes (`gpu_allocated`, `gpu_requested`) on
`node`/`queue`/`project`, not a separate entity.

### Incident / RCA layer — *populated by ingestion*
`alert`, `incident` (owns `analysis_summary` so prior RCA is queryable),
`analysis_run`.

### Knowledge layer — *curated; seeded from the `knowledge/` catalogs*
`symptom` (owns `keyword` for matching), `root_cause`, `action`, plus the
`xid_error` GPU-fault catalog (with `leads_to` chains) and
`control_plane_component` platform topology (with `depends_on`). This is the
"this symptom → this cause → fixed by this action" knowledge the orchestrator
consults. Fed by five loaders — see [How data gets in](#3-how-data-gets-in) and
the [Knowledge Base](KNOWLEDGE-BASE.md) doc.

### Root-cause taxonomy (15 families, `sub root_cause`)
`node_kubelet_pressure`, `runai_scheduling_quota`, `k8s_scheduling_error`,
`runai_control_plane_error`, `k8s_control_plane_error`, `workload_startup_error`,
`image_pull_error`, `gpu_hardware_error`, `network_fabric_error`,
`cluster_network_error`, `k8s_storage_error`, `storage_backend_error`,
`workload_runtime_error`, `observability_accuracy`, `platform_auth_error`
(+ `insufficient_evidence`). Must stay in sync with the loader `FAMILIES` sets and
`agent/app/services/root_cause_ranking.py`; guardrail tests enforce it.

### Relations
- **Topology**: `scopes` (cluster→node/project), `runs_on` (node→pod),
  `belongs_to` (workload→pod), `in_project`, `submitted_to` (workload→queue),
  `contains` (namespace→pod/workload/component), `depends_on` (component→component)
- **Incident**: `grouped_into` (incident←alert), `analyzed_by`, `similar_to`
- **Knowledge**: `has_symptom`, `indicates` (symptom→cause), `has_cause`,
  `fixed_by` (cause→action), `resolved_by` (symptom→action), `supported_by`
  (←evidence), `emits`, `applies_to` (xid→gpu_model), `leads_to` (xid→xid)

### Populated vs modeled
| Status | Entities / relations |
|---|---|
| ✅ Populated (`ontology/ingest.py`) | infra + incident layer + topology/`grouped_into` |
| ✅ Knowledge (`load_knowledge` / `load_xids` / `load_alerts` / `load_known_issues` / `load_architecture`) | `symptom`/`root_cause`/`action` + `indicates`/`resolved_by`, `xid_error` + `leads_to`, `control_plane_component` + `depends_on` |
| 🟦 Promoted (`ingest.py --promote-knowledge`) | `confirmed:<alert>` symptom → family → action, from operator-confirmed RCAs |
| ⬜ Modeled, not yet fed | `evidence`, `runbook`, `analysis_run`, `similar_to`, `supported_by`, GPU attrs |

---

## 3. How data gets in

| Path | Script | Source | Gate |
|---|---|---|---|
| Schema + functions | `load_schema` / `load_functions` | `schema.tql` / `functions.tql` | Helm post-install/upgrade hook (`typedb-schema-job.yaml`) |
| Curated knowledge | `load_knowledge`, `load_xids`, `load_alerts`, `load_known_issues`, `load_architecture` | the `knowledge/` catalogs | Version-controlled files, run in the schema job |
| Topology + incidents | `ontology/ingest.py` (CronJob) | Postgres `incidents`/`alerts` | Resolved ≥ `resolvedGraceHours` ago; review-gated unless `requireReview=false` |
| Knowledge promotion | `ingest.py --promote-knowledge` | operator-confirmed RCAs | Resolved + net-positive feedback |

The **orchestrator** consults TypeDB during analysis
(`agent/app/services/kg_enrichment.py`): node blast radius, prior same-alert
incidents, and graph-derived remediation. It degrades to an empty context when
TypeDB is off/unreachable. Inspect the graph with `python -m ontology.query`
(`--incident` / `--recent` / `--count`) or TypeDB Studio.

---

## 4. Connection / config

| Env | Default | Notes |
|---|---|---|
| `ENABLE_TYPEDB` | `false` (Helm sets it from `typedb.enabled`) | Master switch |
| `TYPEDB_ADDRESS` | `localhost:1729` | In-cluster: `<release>-typedb:1729` |
| `TYPEDB_DATABASE` | `runai_rca` | |
| `TYPEDB_USERNAME` / `TYPEDB_PASSWORD` | `admin` / `password` | CE defaults — override beyond PoC |
| `POSTGRES_DSN` | — | Backend Postgres (also read by agent collectors/ingestion) |
| `RUNAI_DB_DSN` | — | Optional read-only DSN for the **Run:ai control-plane** Postgres; enables the postgres drill-down's `sql_select` over platform schemas (workloads/audit/…). Use a read-only role. |

TypeDB deploys as a single-node `StatefulSet` + PVC
(`charts/runai-rca/templates/typedb.yaml`). Community Edition is single-node;
HA/clustering is the paid Enterprise tier.
