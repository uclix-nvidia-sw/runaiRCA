# Deployment Guide

> **Lens:** How to use — take it from published images to a running deployment.
> **In this doc:** container/Helm publishing · install paths · Alertmanager webhook routing · Postgres & pgvector setup · read-only RBAC.

## Container and Helm Deployment

The repository includes a GitHub Actions workflow that builds the three runtime
images and publishes them to GitHub Container Registry (GHCR), so operators do
not need to build images locally for every deployment:

- `ghcr.io/<owner>/runai-rca-backend`
- `ghcr.io/<owner>/runai-rca-agent`
- `ghcr.io/<owner>/runai-rca-frontend`

The workflow runs on `main` pushes, version tags such as `v0.1.0`, pull
requests, and manual dispatch. Pull requests build the images without pushing.
`main` pushes publish the `main` and `sha-...` tags plus the chart `appVersion`
(for example `0.1.0`), and version tags publish semver tags such as `0.1.0`.

Deploy the published GHCR images with Helm by pointing the global registry at
the GitHub owner or organization namespace and choosing a shared tag:

```bash
helm upgrade --install runai-rca charts/runai-rca \
  --set global.imageRegistry=ghcr.io/<owner> \
  --set backend.image.tag=0.1.0 \
  --set agent.image.tag=0.1.0 \
  --set frontend.image.tag=0.1.0
```

For a release tag like `v0.1.0`, use `--set backend.image.tag=0.1.0` and the
same tag for `agent` and `frontend`. If component image tags are left empty, the
chart defaults them to `appVersion` from `charts/runai-rca/Chart.yaml`.

The Helm chart itself is also packaged and published to GHCR as an OCI artifact
on `main` pushes and version tags. Pull the chart directly instead of cloning the
repository:

```bash
helm upgrade --install runai-rca oci://ghcr.io/<owner>/charts/runai-rca \
  --version 0.1.1 \
  --set global.imageRegistry=ghcr.io/<owner>
```

Local image builds are still available for development.

Each runtime has its own image:

```bash
docker build -t runai-rca-agent:0.1.0 agent
docker build -t runai-rca-backend:0.1.0 backend
docker build -t runai-rca-frontend:0.1.0 frontend
```

The Helm chart deploys the frontend, backend, agent service, read-only
Kubernetes RBAC for evidence collection, and the secret/config boundaries for
Run:ai, Prometheus, Loki, and Postgres.

```bash
helm template runai-rca charts/runai-rca
helm install runai-rca charts/runai-rca \
  --set agent.env.runaiBaseUrl=https://runai.example.com \
  --set agent.env.prometheusUrl=http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090 \
  --set agent.env.lokiUrl=http://loki-read.monitoring.svc.cluster.local:3100 \
  --set-string agent.env.runaiLogNamespaces='runai\,runai-backend' \
  --set secrets.existingSecret=runai-rca-secrets
```

## Alertmanager Webhook Routing

The Backend creates incidents and starts automatic RCA only when Alertmanager
sends `POST /webhook/alertmanager`. If the same alert reaches Slack but does
not appear in Run:AI RCA, Alertmanager is usually routing to the Slack receiver
but not to the RCA webhook receiver.

Use the Backend service directly from inside the cluster:

```text
http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/webhook/alertmanager
```

If Alertmanager must call through the frontend ingress, the bundled nginx config
also proxies `/webhook/` to the Backend:

```text
https://<frontend-host>/webhook/alertmanager
```

A simple combined receiver sends the same routed alert to Slack and RCA:

```yaml
route:
  receiver: slack-and-rca

receivers:
  - name: slack-and-rca
    slack_configs:
      - api_url: <slack-webhook-url>
        channel: <channel>
        send_resolved: false
    webhook_configs:
      - url: http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/webhook/alertmanager
        send_resolved: true
```

Keep `send_resolved: false` on the direct Slack receiver and `send_resolved:
true` on the RCA webhook. The direct receiver continues to post firing alerts;
the Backend posts the resolved transition as a reply under the incident's
initial-analysis message. Enabling resolved delivery on both receivers creates
the extra channel-level resolved message that the threaded flow is designed to
avoid.

When keeping separate receivers, make sure the Slack route does not stop
matching before RCA. One common pattern is `continue: true` on the Slack route:

```yaml
route:
  routes:
    - matchers:
        - alertname=~".*"
      receiver: slack
      continue: true
    - matchers:
        - alertname=~".*"
      receiver: runai-rca

receivers:
  - name: runai-rca
    webhook_configs:
      - url: http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/webhook/alertmanager
        send_resolved: true
```

After a route change, verify both network reachability from the Alertmanager pod
and Backend intake:

```bash
kubectl exec -n <alertmanager-namespace> <alertmanager-pod> -- \
  wget -S -O- http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/healthz

curl -s http://<frontend-or-backend-url>/api/v1/alerts
curl -s http://<frontend-or-backend-url>/api/v1/analysis-runs
```

Create the Kubernetes Secret referenced by `secrets.existingSecret` before
installing the chart. Use the same namespace as the Helm release, keep `.env`
for local development only, and omit keys that your deployment does not use:

```bash
kubectl create namespace runai-rca
kubectl create secret generic runai-rca-secrets \
  --namespace runai-rca \
  --from-literal=RUNAI_CLIENT_ID='<runai-client-id>' \
  --from-literal=RUNAI_CLIENT_SECRET='<runai-client-secret>' \
  --from-literal=RUNAI_BEARER_TOKEN='<optional-runai-token>' \
  --from-literal=NVIDIA_API_KEY='<nim-api-key>' \
  --from-literal=LLM_API_KEY='<llm-api-key>' \
  --from-literal=DATABASE_URL='postgres://user:password@postgres.example.com:5432/runai_rca?sslmode=require' \
  --from-literal=POSTGRES_DSN='postgres://user:password@postgres.example.com:5432/runai_rca?sslmode=require' \
  --from-literal=RUNAI_DB_DSN='<optional: read-only DSN for the Run:ai control-plane Postgres, enables the postgres drill-down>' \
  --from-literal=SLACK_BOT_TOKEN='<optional: xoxb- bot token, chat:write>' \
  --from-literal=SLACK_CHANNEL_ID='<optional: channel for incident-analysis summaries>' \
  --from-literal=SLACK_APP_TOKEN='<optional: xapp- app token, connections:write, for the Re-analyze button>'
```

`RUNAI_DB_DSN` and the three `SLACK_*` keys are optional — omit them to disable
the platform-DB drill-down and Slack notifications respectively. Slack also needs
`backend.env.dashboardUrl` set for the "Open Incident" link.

> **Never commit real token values.** Put every secret in this Kubernetes Secret
> (or your own via `secrets.existingSecret`) — the `SLACK_APP_TOKEN` (`xapp-`),
> `SLACK_BOT_TOKEN` (`xoxb-`), API keys, and DSNs. The chart's `secrets.*` values
> in `values.yaml` default to empty and must stay empty in Git; a real token
> belongs only in the cluster Secret, never in a committed file.

Install into that namespace with `--namespace runai-rca --create-namespace`, or
replace the namespace above with your release namespace. If you use different
Secret key names, set `secrets.keys.*` to match them.

For an existing Postgres, set `secrets.databaseUrl` or provide a Secret through
`secrets.existingSecret`. By default the chart reads `DATABASE_URL` and
`POSTGRES_DSN`; if your existing Secret uses different key names, set
`secrets.keys.databaseUrl` and `secrets.keys.postgresDsn`. The backend
auto-creates the target database on first start if it is missing — it connects to
the server's `postgres` maintenance database, issues a single
`CREATE DATABASE <name>` only when absent, and never touches other databases. The
connecting user therefore needs the `CREATEDB` privilege (or an admin can
pre-create the database). The backend user also needs privileges to create/update tables
(and to run `CREATE EXTENSION` if pgvector should be enabled). pgvector is a database-server prerequisite: the
extension binary must be installed on that Postgres server, and a DBA/admin may
need to run `CREATE EXTENSION IF NOT EXISTS vector;` inside every database such as
`runai_rca` before the backend starts.

For a bundled single-pod Postgres, enable:

```bash
helm install runai-rca charts/runai-rca \
  --set postgresql.enabled=true \
  --set postgresql.auth.password=change-me
```

If `secrets.existingSecret` is used for Run:ai/NVIDIA credentials while bundled
Postgres is enabled, the chart creates a separate generated database Secret and
points Backend/Agent DB variables at it. To use a dedicated existing DB Secret
instead, set `secrets.databaseExistingSecret`.
Bundled Postgres usernames, passwords, and database names are URL-encoded when
the chart generates `DATABASE_URL` / `POSTGRES_DSN`; externally supplied DSNs in
`secrets.databaseUrl`, `secrets.postgresDsn`, or existing Secrets should already
be valid Postgres URLs. The default bundled image is `pgvector/pgvector:pg16`,
which ships the pgvector extension preinstalled, so the bundled database serves
real vector search out of the box. When pgvector is available the backend adds an
`embedding vector(384)` column with an HNSW cosine index and runs similar-incident
search inside Postgres with the `<=>` cosine operator. If pgvector is unavailable
(for example when pointing at an external Postgres without the extension), the
backend logs `pgvector=unavailable, fallback=jsonb` and continues to serve
similar-incident search from JSONB sparse vectors in
`incident_embeddings.vector_json` using in-process cosine similarity.

The Agent uses read-only cluster-wide RBAC by default so it can inspect target
pods, Run:ai control-plane namespaces, and node context. To limit it to selected
namespaces, disable cluster-wide RBAC and list the namespaces that should be
queryable:

```bash
helm upgrade --install runai-rca charts/runai-rca \
  --set agent.rbac.clusterWide=false \
  --set 'agent.rbac.namespaces[0]=runai' \
  --set 'agent.rbac.namespaces[1]=runai-backend' \
  --set 'agent.rbac.namespaces[2]=runai-vision'
```
