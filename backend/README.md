# Run:AI RCA Backend

Go API server for Run:AI RCA.

The MVP intentionally uses the Go standard library and an in-memory store so the
API can be exercised before Postgres credentials are available. The public API
and model names are shaped for a later `pgx` Postgres store with pgvector.

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
| `DATABASE_URL` | empty | Planned Postgres store DSN |
| `POSTGRES_DSN` | empty | Forwarded to Agent diagnostics |
