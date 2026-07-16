# External support-case priors (de-identified)

The `case-<hash>/03_ingestion_payload.yaml` files here are curated external
support cases (schema v2.0 `historical_incident_candidate`), committed **after
de-identification** — the same practice as `knowledge/runai_known_issues.yaml`,
which publishes the lesson but never a traceable case record.

They are baked into the agent image via the existing `COPY knowledge` and loaded
into TypeDB by the Helm schema-load hook (`python -m ontology.load_external_cases`)
as **labelled historical priors** — never knowledge-layer authority (the loader
writes no `indicates`/`resolved_by` edges). At runtime a case surfaces only when
one of its error signatures appears in an analysis' observed evidence.

## De-identification contract (sanitize.py)

Raw curated bundles carry the real support-case number in several fields. They
are **never committed**; `sanitize.py` produces the committable copies:

- drops `identity.source_case_number`, `identity.source_manifest` (filenames
  embed the number) and `ingestion_controls` (prose repeats the key)
- rewrites `deduplication_key` → `enterprise_support:<sha256(orig)[:12]>` and
  `source_system` → `enterprise_support` (vendor removed)
- coarsens `incident.occurred_at` to a date (time/timezone dropped)
- injects `searchable_context.curated_signature_tokens` for cases that have no
  error_signatures (see `_CURATED_TOKENS`), so they stay signature-retrievable
- **refuses to write** any output still containing the original number or key

## Adding or re-curating a case

```sh
cd agent
.venv/bin/python knowledge/external_cases/sanitize.py /path/to/raw_bundles
.venv/bin/python -m ontology.load_external_cases --dry-run   # review the mapping
```

Commit the new `case-<hash>/` directory. If the dry-run shows `kw=0`, add
curated signature tokens for that case's hash in `sanitize.py` and re-run.

## Loading

The Helm `typedb-load-schema` job (post-install/upgrade) runs the loader when
`typedb.externalCases.enabled` is true; `typedb.externalCases.approvedBy` is
required and is recorded on every case as the accountable approver.
