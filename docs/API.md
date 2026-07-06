# API Reference

> **Lens:** Reference — the HTTP surface.
> **In this doc:** Backend endpoints · Agent endpoints · webhook accept/ignore semantics.

## Endpoints

Backend:

- `POST /webhook/alertmanager`
- `GET /api/v1/incidents?view=active|archived|trash`
- `GET /api/v1/incidents/{id}`
- `POST /api/v1/incidents/{id}/analyze`
- `POST /api/v1/incidents/{id}/resolve`
- `POST /api/v1/incidents/{id}/archive`
- `POST /api/v1/incidents/{id}/unarchive`
- `POST /api/v1/incidents/{id}/restore`
- `DELETE /api/v1/incidents/{id}`
- `DELETE /api/v1/incidents/{id}?permanent=true`
- `GET /api/v1/incidents/{id}/feedback`
- `POST /api/v1/incidents/{id}/feedback`
- `POST /api/v1/incidents/{id}/vote`
- `POST /api/v1/incidents/{id}/comments`
- `PUT /api/v1/incidents/{id}/comments/{comment_id}`
- `DELETE /api/v1/incidents/{id}/comments/{comment_id}`
- `GET /api/v1/alerts`
- `GET /api/v1/alerts/{id}`
- `GET /api/v1/alerts/{id}/feedback`
- `POST /api/v1/alerts/{id}/feedback`
- `POST /api/v1/alerts/{id}/vote`
- `POST /api/v1/alerts/{id}/comments`
- `PUT /api/v1/alerts/{id}/comments/{comment_id}`
- `DELETE /api/v1/alerts/{id}/comments/{comment_id}`
- `POST /api/v1/embeddings/search`
- `GET /api/v1/analysis-runs`
- `GET /api/v1/stats/recurrence?days=7`
- `GET /api/v1/events`
- `POST /api/v1/chat`

`POST /webhook/alertmanager` returns HTTP 202 with `status`, `alerts`,
`accepted`, and `ignored` counts. Alerts with severity `info` or `information`
are counted as ignored and do not create incidents, alerts, SSE events, or
analysis runs.

`GET /api/v1/incidents` returns the active incident view by default. Use
`view=archived` for archived incidents and `view=trash` for soft-deleted
incidents that are still inside the trash retention window. Invalid view values
return HTTP 400. List pagination keeps `total` scoped to the selected view.

Incident lifecycle actions:

- `POST /api/v1/incidents/{id}/resolve` toggles the operator's final approval
  for the RCA. It sets or clears `user_approved_at` and does not change
  `status` or `resolved_at`; those remain the Alertmanager incident state.
  Similar-incident memory is loaded only after this approval.
- `POST /api/v1/incidents/{id}/archive` hides an active incident from the active
  list without deleting data. A new matching alert automatically unarchives the
  incident.
- `POST /api/v1/incidents/{id}/unarchive` moves an archived incident back to the
  active view.
- `DELETE /api/v1/incidents/{id}` soft-deletes an incident into the trash view,
  removes it from active matching indexes, and prevents backfill, dashboard,
  chat fallback, and memory search from using it.
- `POST /api/v1/incidents/{id}/restore` restores a soft-deleted incident when its
  matching indexes are not already owned by a newer incident.
- `DELETE /api/v1/incidents/{id}?permanent=true` permanently deletes the incident
  and its alerts, embeddings, feedback, comments, and analysis runs.

`GET /api/v1/stats/recurrence?days=N` returns recurrence statistics for the last
`N` days. `days` defaults to 7, clamps to 1..90, and returns:

```json
{
  "data": {
    "days": 7,
    "rate": 0.5,
    "total": 4,
    "recurred": 2,
    "daily": [{"date": "2026-07-06", "total": 1, "recurred": 1, "rate": 1}]
  }
}
```

Incident responses expose Alertmanager state as `status` / `resolved_at` and
operator final approval as `user_approved_at`. `AnalysisRun` responses include
optional `metadata`. LLM token accounting is stored under `metadata.llm_usage`
when the agent returns usage data. Incident detail responses expose the latest
run usage as `token_usage`, and include `similar_recent_count` for the recent
similar-incident count shown in the UI.

`GET /api/v1/events` emits named SSE events. Incident archive, unarchive,
delete, restore, and manual permanent delete changes emit `incident.updated` so
other dashboard sessions can refresh the active, archived, and trash views.

Agent:

- `POST /analyze`
- `POST /summarize-incident`
- `POST /chat` context-aware RCA chat grounded in current incidents, alerts, evidence, feedback, and similar RCA memory
- `GET /healthz`
