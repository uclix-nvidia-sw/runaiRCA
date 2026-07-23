# Operations & Troubleshooting

> **Lens:** Running the RCA platform itself — how to confirm it works and what to
> check when it doesn't.
> **In this doc:** health checks · "no RCA report" causes · TypeDB / pgvector /
> Slack diagnostics · inspecting the knowledge graph · common failure signatures.

This is about operating **Run:AI RCA**, not the incidents it analyzes. For the
analysis flow see [RCA Pipeline](RCA-PIPELINE.md); for the stores see
[Data Stores](DATABASE.md).

**Who this is for:** the on-call person operating the RCA service itself. Start
with “Is it actually working?” to trace alert intake, then use the subsystem
sections only for the dependency that is failing. A healthy process is not the
same thing as a completed evidence collection.

## Is it actually working?

An automatic RCA only starts after **Alertmanager posts to the Backend
webhook** — a Slack notification from Alertmanager alone does not prove the RCA
receiver was routed. Confirm the live path:

```bash
# Alerts and analysis runs the backend has actually received/started
curl -s http://<backend-or-frontend>/api/v1/alerts | jq '.[0]'
curl -s http://<backend-or-frontend>/api/v1/analysis-runs | jq '.[0]'

# Agent process liveness (means the API is up, NOT that a collector produced evidence)
curl -s http://<agent>/healthz
```

- Collector cards in the UI turn **`ok` only after a run stores collector
  `artifacts`** — a `Running` pod or a `200` health check is not enough.
- The Agent health payload also lists `collectors.active` and
  `collectors.unknown`. An unknown configured name means that evidence plane is
  absent; the same condition is added to each analysis as a warning.
- `ENABLE_NAT_RUNTIME=true` affects `/analyze` synthesis; `/chat` returns a
  deterministic context answer and does not call the LLM path directly.

## "No RCA report was produced"

Work down this list — the usual causes, most common first:

1. **Alertmanager isn't routed to the webhook.** The alert reached Slack but not
   `POST /webhook/alertmanager`. Check the Alertmanager receiver/route (see
   [Deployment](DEPLOYMENT.md)); the alert won't appear in `/api/v1/alerts`.
2. **The alert resolved and was skipped.** Resolved alerts are intentionally not
   analyzed. Expected.
3. **Fan-out / rate caps.** A burst exceeded `MAX_AUTO_ANALYZE_FANOUT` (per
   webhook) or `MAX_CONCURRENT_AGENT_RUNS`. The backfill loop
   (`ANALYSIS_BACKFILL_INTERVAL_SECONDS`) re-drives dropped alerts — wait a cycle
   or raise the caps.
4. **Auto re-analysis cooldown.** If an alert re-fired but no new run appeared,
   it may still be inside the auto re-analysis cooldown (default 360 minutes), so
   the existing run was reused instead.
5. **Backend hung up before the agent finished.** If
   `AGENT_REQUEST_TIMEOUT_SECONDS` (960) is ever set below the agent's
   `ANALYSIS_DEADLINE_SECONDS` (900), the backend cancels mid-analysis and the
   degraded report is lost. Keep backend > agent.
6. **Persist failure is intentional early-return.** The backend early-returns if
   it cannot persist a run; this is by design (and tested), not a bug. Check the
   backend logs and Postgres health.

A run stuck in `analyzing` past its timeout is reaped to `failed` on the next
backend start (`ReapStaleAnalyzingRuns`); it won't hang forever.

## TypeDB (ontology) diagnostics

The graph is optional — when it's off/unreachable, analysis still runs and the
report simply omits the Knowledge Base section (the reason lands in `warnings`).

```bash
# Did the schema/knowledge load job run?
kubectl get jobs -n <ns> | grep typedb
kubectl logs -n <ns> job/<release>-typedb-load-schema

# Did the ingest cron project incidents?
kubectl get cronjob,jobs -n <ns> | grep ingest
kubectl logs -n <ns> job/$(kubectl get jobs -n <ns> -o name | grep ingest | tail -1 | cut -d/ -f2)
# → "fetched N incident(s); ingesting M ... done: X written"

# Inspect the graph without writing TypeQL
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --recent 20
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --incident INC-...
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --count
```

- **Graph looks empty?** Ingest only projects incidents **resolved ≥
  `resolvedGraceHours` (6h) ago**; a fresh cluster simply has nothing eligible
  yet. If `--recent` returns rows but one incident is missing, that incident's
  `resolved_at` may be null (UI "Resolved" ≠ DB `resolved_at` set).
- **`warnings` says "TypeDB knowledge-graph query failed (...)"** — the message
  names the cause (connection refused vs auth vs a `[TQLxx]` query error). It is
  never silently swallowed.
- Re-run ingest on demand:
  `kubectl create job -n <ns> --from=cronjob/<release>-typedb-ingest manual-ingest-1`.

### Reasoning-trace v3-only migration

The v3-only upgrade irreversibly removes `reasoning_trace_v2` and `stop_reason`
from Postgres metadata, CaseSnapshots, and stored Knowledge Candidate traces.
Back up Postgres and TypeDB before upgrading. Pause new analyses and suspend the
TypeDB ingest/backfill jobs until no analysis run is `analyzing`; an old writer
cannot write `trace_stop_reason` after the schema type is removed.

The Backend startup migration removes the retired JSON keys in one transaction,
recomputes affected candidate content hashes, and logs affected row counts. The
TypeDB schema Job then deletes attribute ownerships and instances before
undefining the ownership and type. Both migrations are idempotent. Treat either
migration failure as a failed rollout; legacy trace contents can be restored
only from the pre-upgrade backup.

### Trace-v3 backfill and empty investigation traces

The `typedb-trace-v3-backfill` Job runs as a Helm `post-install` / `post-upgrade`
hook. Helm deletes a successful hook Job, so not finding a completed Job later is
normal. Check the release events or run the backfill command manually when you
need an audit trail.

```bash
# Run one bounded, idempotent page manually; it does not invent missing traces.
kubectl exec -n <ns> deploy/<release>-agent -- \
  python -m ontology.backfill_trace_v3 --batch-size 200 --max-batches 1
```

`0 written` is not an error by itself. `hypothesis` and `probe_execution` are
created only from an active, Dashboard-approved CaseSnapshot carrying an explicit
`reasoning_trace_v3` (or `trace_v3`) record. Trace-less, pre-v3, and inactive
snapshots remain intentionally unconverted. Re-analyze and approve the case to
create an eligible trace-v3 snapshot, then run the backfill again.

See [Knowledge Base → Querying the graph](KNOWLEDGE-BASE.md#querying-the-graph)
for TypeDB Studio access.

## Grafana MCP (Prometheus / Loki) diagnostics

Prometheus and Loki use the same managed `grafanaMcp` service, but they are
separate Grafana datasources. A successful Prometheus query therefore does not
prove that the Loki datasource is visible or queryable. The collectors try MCP
first, then fall back to `PROMETHEUS_URL` or `LOKI_URL`; the collector artifact
records which path supplied evidence.

For an Alertmanager alert with `startsAt`, Loki queries use the incident window:
five minutes before the alert through five minutes after `endsAt`. A firing
alert without an end time is capped at 15 minutes after it started. The direct
Loki API receives `start`/`end`; Grafana MCP receives
`startRfc3339`/`endRfc3339`.
Alerts without a parseable start time retain the datasource's normal recent
window.

Direct Prometheus/Loki responses retain transport provenance: an empty native
Prometheus vector can establish scoped absence, while an empty MCP/proxy result
is context only. Loki verification examines the full returned lines (not the
display sample); its GPU failure query includes OOM, killed-process, NCCL
WARN/ERROR, CUDA error, Xid, NVRM, panic, and segfault forms.

```bash
# Grafana MCP must see both datasource UIDs in the configured organization.
kubectl logs -n <ns> deploy/<release>-grafana-mcp --tail=200

# Inspect the service endpoint and the MCP pod's configured Grafana target.
kubectl get svc -n <ns> <release>-grafana-mcp
kubectl get pod -n <ns> -l app.kubernetes.io/component=grafana-mcp \
  -o jsonpath='{range .items[*]}{.spec.containers[0].env[?(@.name=="GRAFANA_URL")].value}{"\n"}{end}'
```

- **`get datasource by uid ... 400 id is invalid`** — verify that
  `GRAFANA_SERVICE_ACCOUNT_TOKEN` is present in the chart secret, that
  `grafanaMcp.grafanaUrl` reaches Grafana from inside the cluster, and that
  `grafanaMcp.grafanaOrgId` matches the Loki datasource's organization. The
  datasource UID must be the concrete value returned by Grafana; a literal
  `{uid}` path is invalid.
- **MCP lists Prometheus but not Loki** — create or expose the Loki datasource
  in that Grafana organization and grant the service account datasource query
  access. This is a datasource/RBAC problem, not a Loki gateway credential
  problem.
- **MCP fails but direct Loki evidence succeeds** — keep `LOKI_URL` pointed at
  the in-cluster read service (normally `loki-read:3100`) while fixing Grafana
  MCP. This is the intended graceful fallback, but it lacks MCP-specific
  datasource semantics.

## pgvector diagnostics

pgvector is owned by the **backend**. It degrades gracefully to a JSONB
sparse-vector cosine fallback, so similar-incident search always works.

- Startup logs report `pgvector=enabled` or
  `pgvector=unavailable, fallback=jsonb`.
- `unavailable` means the `vector` extension isn't installed or the app user
  can't `CREATE EXTENSION vector`. The bundled `pgvector/pgvector:pg16` image
  ships it; for external Postgres a DBA must install it (see
  [Backend README](../backend/README.md)).
- Similar incidents feed the agent through the `/analyze` request payload
  (`similar_incidents` + `feedback_hints`) — the agent never queries pgvector
  directly.

## Slack diagnostics

Notifications require a **bot token** (`SLACK_BOT_TOKEN` + `SLACK_CHANNEL_ID`),
not an incoming webhook (`chat.postMessage` returns the `ts` needed to thread).

- **Nothing posts?** Confirm both env vars are set, the token has `chat:write`,
  and the **bot is invited to the channel**. Delivery is fire-and-forget — a
  failure is logged (`slack notify failed for incident ...`) and never blocks the
  run.
- **Only some runs post.** By design: only the **first** completed analysis of an
  incident (root message) and later **operator-driven** re-analyses
  (`manual`/`comment`/`feedback`/`chat`, as thread replies) post. Auto/backfill
  follow-ups and failed runs are intentionally silent.
- **Resolved messages appear separately.** Set `send_resolved: false` on the
  direct Alertmanager Slack receiver and keep it `true` on the RCA webhook.
  The Backend then posts the resolved transition in the initial-analysis thread.
- The **Open Incident** button needs `DASHBOARD_URL` set. The **Re-analyze**
  button needs `SLACK_APP_TOKEN` (Socket Mode + Interactivity enabled in the app).

### Slack notifications fail with invalid_auth

Symptom: backend logs show `slack socket mode connected`, but every completed
analysis logs `slack notify failed for incident ...: slack API error:
invalid_auth`. Socket Mode can still work because it uses the app-level
`SLACK_APP_TOKEN` (`xapp-`), while posting uses the bot token
`SLACK_BOT_TOKEN` (`xoxb-`).

The usual causes are a Slack app reinstall, which reissues the Bot User OAuth
Token and invalidates the old `xoxb-`, or an `xapp-` token pasted into the bot
token slot.

Diagnose on the cluster:

```bash
SECRET=$(kubectl get secret -n runai-rca -o name | grep -i secret | head -1)
kubectl get $SECRET -n runai-rca -o jsonpath='{.data.SLACK_BOT_TOKEN}' | base64 -d | cut -c1-5   # expect xoxb-
TOKEN=$(kubectl get $SECRET -n runai-rca -o jsonpath='{.data.SLACK_BOT_TOKEN}' | base64 -d)
curl -s -H "Authorization: Bearer $TOKEN" https://slack.com/api/auth.test                        # {"ok":false,"error":"invalid_auth"} = reissue needed
```

Fix: reissue the Bot User OAuth Token in `api.slack.com/apps` -> **OAuth &
Permissions**. Reinstalling the app rotates the `xoxb-` token. Then update the
cluster secret:

```bash
helm upgrade --reuse-values --set secrets.slackBotToken='xoxb-...' <release> <chart>
# or:
kubectl patch secret $SECRET -n runai-rca --type merge -p '{"stringData":{"SLACK_BOT_TOKEN":"xoxb-..."}}'
kubectl rollout restart deploy/<backend> -n runai-rca
```

Verify `/healthz` reports `slack.auth=ok` and a fresh completed analysis reaches
the channel. The backend also logs a transition line such as `slack:
notifications are FAILING (invalid_auth) since ...` when posting first fails.

## Evidence looks thin

If a collector card is `unavailable` or a report says *"증거를 찾기 어렵습니다"*:

- That collector's data source isn't configured/reachable (e.g. `LOKI_URL`,
  `PROMETHEUS_URL`, `SYSTEM_AGENT_URL` unset). The report names the missing
  source rather than inventing a cause — this is the honesty gate, not a bug.
- Per-step ceilings are generous (120s) on purpose; don't shrink them to
  "optimize" — that reintroduces shallow evidence. Tune
  `ANALYSIS_DEADLINE_SECONDS` instead if latency matters.
- To let agents dig deeper, ensure `ENABLE_INVESTIGATION_LOOP` and
  `ENABLE_AGENT_DRILLDOWN` are on (Helm defaults true) and an LLM is configured —
  without an LLM these loops are skipped and evidence is one-shot.

## Where to look

| Symptom | First check |
|---|---|
| No alerts at all | Alertmanager route → `/api/v1/alerts` |
| Alerts but no runs | `/api/v1/analysis-runs`, fan-out/rate caps, agent `/healthz` |
| Runs `failed` | backend logs, agent deadline vs backend timeout |
| Empty Knowledge Base section | TypeDB reachable? ingest ran? `warnings` field |
| No similar incidents | pgvector startup log, embeddings table populated |
| No Slack message | bot token + channel + bot invited; run source eligible |
| Thin evidence | data-source URLs set; LLM configured for drill-down |
