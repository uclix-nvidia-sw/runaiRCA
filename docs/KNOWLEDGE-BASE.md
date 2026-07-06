# Knowledge Base

> **Lens:** What the Agent *knows* before it sees an incident — the curated
> catalogs and the ontology graph that ground every RCA.
> **In this doc:** the five curated catalogs · platform-architecture topology ·
> file ↔ TypeDB dual-load · ingestion & knowledge promotion · querying the graph.

Curated knowledge is **dual-loaded**: a file matcher in
`agent/app/knowledge.py` (works with **no TypeDB** — always available) *and* a
TypeDB loader (`agent/ontology/load_*.py`) that mirrors the same facts into the
graph. The invariant: RCA is fully functional with TypeDB off; TypeDB is the
"turn it on to get smarter" layer, never a hard dependency.

## Curated catalogs

All live under `agent/knowledge/` and ship in the agent image.

| Catalog | File | Recognised by | Used for |
|---|---|---|---|
| **Failure modes** | `failure_modes.yaml` | symptom keywords (across all families) | precise remediation actions per symptom |
| **Run:ai known issues** | `runai_known_issues.yaml` | signature keywords, version-aware | headline the specific bug + affected/fixed version |
| **Built-in alerts** | `runai_alerts_catalog.yaml` | alert name | recognise a documented Run:ai alert and its fix |
| **NVIDIA XID catalog** | `xid_catalog.yaml` | XID code | GPU-hardware fault path + causal chains |
| **Platform architecture** | `runai_architecture.yaml` | component name (via symptom `component:` tag) | dependency check paths + DB schema hints |

Matching is substring-first (precise) with a conservative **BM25 + synonym**
recall fallback (`agent/app/bm25.py`) when nothing matches — see the
[RCA Pipeline](RCA-PIPELINE.md#5-signature-matching--bm25-recall--ranking).

### Root-cause families (15)

The taxonomy is the ontology spine and the honesty gate. The deterministic ranker
scores a subset; **signature promotion** headlines the rest (so
`gpu_hardware_error` and the known-issue families still surface even though the
ranker cannot nominate them).

`node_kubelet_pressure`, `runai_scheduling_quota`, `k8s_scheduling_error`,
`runai_control_plane_error`, `k8s_control_plane_error`, `workload_startup_error`,
`image_pull_error`, `gpu_hardware_error`, `network_fabric_error`,
`cluster_network_error`, `k8s_storage_error`, `storage_backend_error`,
`workload_runtime_error`, `observability_accuracy`, `platform_auth_error`
(+ `insufficient_evidence`).

Adding a family = `schema.tql` sub-type + `failure_modes.yaml` block + both loader
`FAMILIES` sets + orchestrator `_family_label`/`_FAMILY_EXPLANATION`. The ranker is
not touched. Guardrail tests enforce schema ↔ loader sync.

## Platform architecture topology

`knowledge/runai_architecture.yaml` is the component map curated from the Run:ai
platform/control-plane architecture diagrams, with names **calibrated against a
live self-hosted cluster** (`kubectl get deploy,ds,sts -n runai / -n
runai-backend`). ~35 components across the cluster side and the `runai-backend`
control plane. Each entry:

| Field | Meaning |
|---|---|
| `layer` | `cluster` · `control_plane` · `external` |
| `purpose` / `failure_effect` | what it does / what breaks when it's down |
| `depends_on` | components it needs — the troubleshooting order |
| `owns_schema` | the control-plane Postgres schema it owns |
| `checks` | ready-to-run `kubectl` commands |

Three consumers (`agent/app/knowledge.py`):

1. **Check paths** — `failure_modes.yaml` symptoms carry `component:`; the
   playbook renders that component's failure effect, its `dependency_path()` BFS
   check order, and its checks.
2. **DB schema hints** — the postgres drill-down's `sql_select` description is
   enriched with schema ownership (`workloads = runai-backend-workloads; audit =
   runai-backend-audit-service; …`).
3. **Graph joins** — mirrored to TypeDB (`control_plane_component` + `depends_on`)
   for future joins with live incident facts.

## TypeDB ontology

An optional TypeDB 3.x knowledge graph (`typedb.enabled`, Helm default **on**)
gives the orchestrator relational reasoning that pgvector similarity and label
overlap cannot express. Schema: `agent/ontology/schema.tql`. It is consulted
**by the orchestrator** around synthesis time — not by a separate agent, and not
as a parallel collector.

**Layers**
- *Infra / topology* — `cluster`, `node`, `namespace`, `project`, `queue`,
  `workload`, `pod`, `control_plane_component` (with `depends_on`).
- *Incident / RCA* — `alert`, `incident` (owns `analysis_summary` so prior RCA is
  queryable), `analysis_run`.
- *Knowledge* — `symptom` (owns `keyword`), `root_cause`, `action`, plus the
  `xid_error` GPU-fault catalog with `leads_to` causal chains.

**Reasoning functions** (`ontology/functions.tql`, validated TypeQL 3.11.x):
`fixes_for_family`, `fixes_for_xid`, `xids_for_gpu_model`, `root_xids_for`.

### How data gets in

| Path | Loader | Source | Gate |
|---|---|---|---|
| Schema + functions | `load_schema` / `load_functions` | `schema.tql` / `functions.tql` | Helm post-install/upgrade hook |
| Curated knowledge | `load_knowledge`, `load_xids`, `load_alerts`, `load_known_issues`, `load_architecture` | the catalogs above | version-controlled files, run in the schema job |
| Incidents + topology | `ontology/ingest.py` (cron) | Postgres `incidents`/`alerts` | resolved ≥ `resolvedGraceHours` ago; review-gated unless `requireReview=false` |
| Knowledge promotion | `ingest.py --promote-knowledge` | operator-confirmed RCAs | resolved + net-positive feedback → `confirmed:<alert>` symptom |

The ingest **CronJob** (`typedb.ingest.schedule`, default every 3h) projects
resolved incidents into the graph. The grace window lets late feedback /
re-analysis settle; re-fired incidents flip back to `firing` and are excluded.
With `requireReview: false` (default) it ingests resolved incidents regardless of
review — flip to `true` to keep unreviewed auto-analysis out of the graph.

### Querying the graph

`ontology/query.py` is a read-only introspection CLI — verify what the ingest
actually projected without hand-writing TypeQL:

```bash
kubectl exec -n <ns> deploy/<release>-agent -- \
  python -m ontology.query --incident INC-...-000023   # one incident
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --recent 20
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --count
```

Or connect **TypeDB Studio** by port-forwarding the server
(`kubectl port-forward svc/<release>-typedb 1729:1729 8000:8000`) and connecting
to `localhost:1729` (db `runai_rca`, `admin`/`password`, TLS off). Example — prior
incidents for an alert, the exact query `enrich()` runs:

```typeql
match
  $a isa alert, has alert_name "Memory major page faults ...";
  (incident: $i, member: $a) isa grouped_into;
  $i isa incident, has incident_id $iid, has analysis_summary $sum;
select $iid, $sum;
```

## See also

- [Data Stores](DATABASE.md) — table-level reference for both stores.
- [RCA Pipeline](RCA-PIPELINE.md) — how this knowledge is consumed during analysis.
