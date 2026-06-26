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
Startup logs report either `pgvector=enabled` or
`pgvector=unavailable, fallback=jsonb`.

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

## Existing Postgres Prerequisites

Using an existing Postgres server requires more than a DSN. The target database
must already exist, the backend user must be able to create and update the RCA
tables, and true pgvector readiness requires the pgvector extension binary to be
installed on the DB server. `CREATE EXTENSION vector;` must be run in each
database the backend connects to, such as `runai_rca`.

If the backend user is allowed to create extensions, startup runs:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

If extension creation is restricted, a DBA/admin should run it before backend
startup. A typical prerequisite script is:

```sql
CREATE DATABASE runai_rca;
CREATE USER runai_rca WITH PASSWORD '<change-me>';
GRANT CONNECT ON DATABASE runai_rca TO runai_rca;

\c runai_rca
CREATE EXTENSION IF NOT EXISTS vector;
GRANT USAGE, CREATE ON SCHEMA public TO runai_rca;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO runai_rca;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO runai_rca;
```

When pgvector is unavailable or the app user cannot create the extension, the
backend still starts and keeps similar-incident memory in
`incident_embeddings.vector_json` using JSONB sparse vectors. The current search
implementation intentionally remains JSONB-backed because the backend stores
sparse text-token vectors rather than fixed-dimension dense embeddings. A real
pgvector column/index should be added when a dense embedding model and dimension
are introduced.

The Helm bundled Postgres default image is `postgres:16-alpine`; do not assume it
contains pgvector. For external Postgres, Helm only provides `DATABASE_URL` /
`POSTGRES_DSN`; pgvector installation and extension creation remain the
responsibility of the existing Postgres operator.

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
