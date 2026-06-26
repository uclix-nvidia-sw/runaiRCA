# Run:AI RCA Backend

Go API server for Run:AI RCA.

The backend uses an in-memory store when no database is configured and upgrades
to Postgres when `DATABASE_URL` or `POSTGRES_DSN` is present. The Postgres store
persists incidents, alerts, similar-incident vectors, feedback votes, markdown
comments, and independent analysis runs created from comments or chat requests.

On startup it creates:

- `incidents`
- `alerts`
- `incident_embeddings`
- `rca_feedback`
- `rca_comments`
- `analysis_runs`

The backend attempts to enable `pgvector`. If the extension is unavailable, it
continues with JSONB sparse vectors so similar-incident search remains usable.

## Run

```bash
go run .
```

## Test

```bash
go test ./...
```

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `AGENT_URL` | `http://localhost:8000` | Agent API base URL |
| `AGENT_REQUEST_TIMEOUT_SECONDS` | `180` | Timeout for Agent `/analyze` and `/chat` requests |
| `DATABASE_URL` | empty | Postgres store DSN |
| `POSTGRES_DSN` | empty | Fallback store DSN and Agent diagnostic DSN |
| `DATABASE_CONNECT_TIMEOUT_SECONDS` | `5` | Startup timeout for Postgres connection and schema initialization |

## RCA Memory APIs

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/embeddings/search` | Search prior incident embeddings |
| `GET` | `/api/v1/incidents/{id}/feedback` | Read incident feedback summary |
| `POST` | `/api/v1/incidents/{id}/feedback` | Add incident vote and optional note |
| `POST` | `/api/v1/incidents/{id}/comments` | Add incident markdown comment |
| `PUT` | `/api/v1/incidents/{id}/comments/{comment_id}` | Update incident comment |
| `DELETE` | `/api/v1/incidents/{id}/comments/{comment_id}` | Delete incident comment |
| `GET` | `/api/v1/alerts/{id}/feedback` | Read alert feedback summary |
| `POST` | `/api/v1/alerts/{id}/feedback` | Add alert vote and optional note |
| `POST` | `/api/v1/alerts/{id}/comments` | Add alert markdown comment |
| `PUT` | `/api/v1/alerts/{id}/comments/{comment_id}` | Update alert comment |
| `DELETE` | `/api/v1/alerts/{id}/comments/{comment_id}` | Delete alert comment |
| `GET` | `/api/v1/analysis-runs` | List comment/chat-triggered analysis runs |
