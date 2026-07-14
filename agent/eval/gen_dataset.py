"""Deterministic generator for the RCA family-classification dataset.

Turns the team's ontology knowledge (knowledge/*.yaml) and operator-confirmed
incidents into `expected_family` answer-key rows, so the eval set grows with the
knowledge base instead of being hand-maintained. No LLM: every row is derived
deterministically, so re-running is idempotent (stable ids + sorted output).

Three stores, with a strict invariant — the MEASURED set only ever gains rows via
a human ("manual" hand rows) or an explicit operator family evaluation plus
incident approval; synthetic rows and model-selected families never auto-enter
measurement:

    eval/nat_dataset.jsonl            MEASURED. Hand rows (preserved verbatim) +
                                      approve-promoted confirmed incidents
                                      (materialized from the store via --export-curated).
    eval/nat_dataset.synthetic.jsonl  Regression-only. 100% generator-owned,
                                      fully regenerated from knowledge/*.yaml.
    rca_dataset (Postgres table)      Durable accumulation of operator-labeled
                                      incident rows; the 3h ingest cron upserts
                                      here and approval flips pending -> approved.

Row shape (backward-compatible with the existing hand rows; the extra `meta`
block is ignored by the rca_family evaluator, which reads question/answer only):

    {"id", "question": {"alert": {status, labels, annotations, fingerprint}},
     "answer": {"expected_family"}, "meta": {source, origin, ...}}

Usage:
    cd agent && python -m eval.gen_dataset --from-ontology            # synthetic file
    cd agent && python -m eval.gen_dataset --from-incidents           # accumulate into rca_dataset
    cd agent && python -m eval.gen_dataset --export-curated           # rca_dataset(approved) -> curated
    cd agent && python -m eval.gen_dataset --from-ontology --dry-run  # counts only
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

# --- layout ------------------------------------------------------------------

_KNOWLEDGE_DIR = Path(os.getenv("KNOWLEDGE_DIR", "knowledge"))
_EVAL_DIR = Path(os.getenv("EVAL_DIR", "eval"))

CURATED_FILE = "nat_dataset.jsonl"
SYNTHETIC_FILE = "nat_dataset.synthetic.jsonl"

# A row is generator-owned (regenerated each run) iff meta.source is one of these.
# Anything else in the curated file — including rows with NO meta — is a hand row
# and is preserved verbatim.
_GEN_SOURCES = {"synthetic", "confirmed"}

# Durable accumulation store for the STATEFUL part of the dataset (confirmed /
# pending incident rows). Synthetic rows stay file-only (deterministic → git).
# Owned by the learning pipeline (this module + the 3h ingest cron), separate
# from the app's operational tables. Created idempotently on first write.
DATASET_TABLE = "rca_dataset"

_DATASET_DDL = f"""
CREATE TABLE IF NOT EXISTS {DATASET_TABLE} (
    dataset_id TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL DEFAULT '',
    incident_id TEXT NOT NULL DEFAULT '',
    alertname TEXT NOT NULL DEFAULT '',
    expected_family TEXT NOT NULL DEFAULT '',
    label_source TEXT NOT NULL DEFAULT '',
    question JSONB NOT NULL,
    approved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

_DATASET_MIGRATIONS = (
    f"ALTER TABLE {DATASET_TABLE} ADD COLUMN IF NOT EXISTS label_source TEXT NOT NULL DEFAULT ''",
)

_DATASET_UPSERT = f"""
INSERT INTO {DATASET_TABLE}
    (dataset_id, source, origin, incident_id, alertname, expected_family, label_source, question, approved, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, now())
ON CONFLICT (dataset_id) DO UPDATE SET
    source = EXCLUDED.source,
    origin = EXCLUDED.origin,
    incident_id = EXCLUDED.incident_id,
    alertname = EXCLUDED.alertname,
    expected_family = EXCLUDED.expected_family,
    label_source = EXCLUDED.label_source,
    question = EXCLUDED.question,
    approved = EXCLUDED.approved,
    updated_at = now()
"""

_DATASET_RECONCILE = f"""
WITH row_state AS (
    SELECT d.dataset_id,
           EXISTS (
               SELECT 1
                 FROM rca_case_snapshots cs
                WHERE cs.incident_id = d.incident_id
                  AND cs.approval_state = 'active'
                  AND EXISTS (
                      SELECT 1
                        FROM rca_eval_reviews er
                       WHERE er.run_id = cs.run_id
                         AND er.analysis_hash = cs.analysis_hash
                         AND er.case_type IN ('known', 'compositional', 'tool_degraded')
                         AND er.expected_family = d.expected_family
                         AND er.expected_family <> ''
                  )
                  AND NOT EXISTS (
                      SELECT 1
                        FROM rca_eval_reviews er
                       WHERE er.run_id = cs.run_id
                         AND er.analysis_hash = cs.analysis_hash
                         AND (
                             er.case_type NOT IN ('known', 'compositional', 'tool_degraded')
                             OR (
                                 er.expected_family <> ''
                                 AND er.expected_family <> d.expected_family
                             )
                         )
                  )
           ) AS label_valid,
           EXISTS (
               SELECT 1
                 FROM incidents i
                WHERE i.incident_id = d.incident_id
                  AND i.status = 'resolved'
                  AND i.resolved_at IS NOT NULL
                  AND i.resolved_at < now() - make_interval(hours => $1::int)
                  AND i.user_approved_at IS NOT NULL
           ) AS incident_approved
      FROM {DATASET_TABLE} d
     WHERE d.source = 'confirmed'
)
UPDATE {DATASET_TABLE} d
   SET label_source = CASE
                          WHEN state.label_valid THEN 'operator_evaluation'
                          ELSE ''
                      END,
       approved = state.label_valid AND state.incident_approved,
       updated_at = now()
  FROM row_state state
 WHERE d.dataset_id = state.dataset_id
"""

# --- family -> plausible alertname / topology --------------------------------
# The discriminating signal for the classifier lives in the annotation text; the
# alertname just needs to be plausible and STABLE (so ids/diffs stay deterministic).
_FAMILY_ALERTNAME: dict[str, str] = {
    "workload_startup_error": "KubePodCrashLooping",
    "workload_runtime_error": "KubeContainerRuntimeError",
    "image_pull_error": "KubePodImagePullBackOff",
    "k8s_scheduling_error": "KubePodFailedScheduling",
    "k8s_storage_error": "KubePersistentVolumeError",
    "k8s_control_plane_error": "KubeControlPlaneError",
    "storage_backend_error": "StorageBackendError",
    "runai_scheduling_quota": "RunAIWorkloadPending",
    "runai_control_plane_error": "RunAIControlPlaneError",
    "node_kubelet_pressure": "KubeNodeConditionPressure",
    "gpu_hardware_error": "GPUHardwareFault",
    "network_fabric_error": "GPUFabricError",
    "cluster_network_error": "KubeClusterNetworkError",
    "observability_accuracy": "RunAIMetricAccuracyIssue",
    "platform_auth_error": "RunAIAuthError",
    "platform_version_bug": "RunAIKnownIssue",
    "expected_known_behavior": "RunAIKnownBehavior",
}

# Families whose evidence is node-scoped vs run:ai-control-plane-scoped; the rest
# get a workload (namespace/pod) target.
_NODE_FAMILIES = {"node_kubelet_pressure", "gpu_hardware_error", "network_fabric_error"}
_RUNAI_FAMILIES = {
    "runai_scheduling_quota",
    "runai_control_plane_error",
    "observability_accuracy",
    "platform_auth_error",
    "platform_version_bug",
    "expected_known_behavior",
}


# --- helpers -----------------------------------------------------------------

def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return re.sub(r"-{2,}", "-", s)


def _alertname_for(family: str) -> str:
    return _FAMILY_ALERTNAME.get(family, "Synthetic" + "".join(p.capitalize() for p in family.split("_")))


def _labels_for(family: str, name_hint: str) -> dict[str, str]:
    if family in _NODE_FAMILIES:
        return {"node": f"gpu-node-{_slug(name_hint)[:24] or 'x'}"}
    if family in _RUNAI_FAMILIES:
        return {"namespace": "runai"}
    return {"namespace": "team-synthetic", "pod": f"workload-{_slug(name_hint)[:24] or '0'}"}


def _fingerprint(*parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"fp-gen-{digest}"


def _row(
    *,
    row_id: str,
    alertname: str,
    labels_extra: dict[str, str],
    annotations: dict[str, str],
    expected_family: str,
    source: str,
    origin: str,
    fingerprint: str | None = None,
    extra_meta: dict[str, Any] | None = None,
    labels_override: dict[str, str] | None = None,
) -> dict[str, Any]:
    labels = labels_override if labels_override is not None else {"alertname": alertname, **labels_extra}
    if "alertname" not in labels:
        labels = {"alertname": alertname, **labels}
    fp = fingerprint or _fingerprint(row_id, expected_family)
    meta: dict[str, Any] = {"source": source, "origin": origin}
    if extra_meta:
        meta.update(extra_meta)
    return {
        "id": row_id,
        "question": {
            "alert": {
                "status": "firing",
                "labels": labels,
                "annotations": annotations,
                "fingerprint": fp,
            }
        },
        "answer": {"expected_family": expected_family},
        "meta": meta,
    }


def _signature(row: dict[str, Any]) -> tuple[str, str, str]:
    """Dedup key: (alertname, expected_family, normalized annotation hash)."""
    alert = row["question"]["alert"]
    alertname = str(alert.get("labels", {}).get("alertname", ""))
    family = str(row.get("answer", {}).get("expected_family", ""))
    text = " ".join(str(v) for v in sorted(alert.get("annotations", {}).values()))
    text = re.sub(r"\s+", " ", text.lower()).strip()
    return (alertname, family, hashlib.sha1(text.encode("utf-8")).hexdigest()[:12])


# --- synthetic generation (pure: takes parsed catalogs) ----------------------

def gen_xid_rows(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """Every XID -> gpu_hardware_error. Full catalog goes to the regression file."""
    rows: list[dict[str, Any]] = []
    for entry in catalog.get("xids", []) or []:
        code = entry.get("code")
        if code is None:
            continue
        mnemonic = str(entry.get("mnemonic") or "").strip()
        desc = str(entry.get("description") or "").strip()
        summary = f"NVRM: Xid {code}: {mnemonic}".strip().rstrip(":")
        annotations = {"summary": summary}
        if desc:
            annotations["description"] = f"Xid {code} {mnemonic}: {desc}"
        rows.append(
            _row(
                row_id=f"synthetic:xid-{code}",
                alertname="NVRMXidCritical",
                labels_extra={"node": f"dgx-x{int(code):03d}"} if isinstance(code, int) else {"node": "dgx-xid"},
                annotations=annotations,
                expected_family="gpu_hardware_error",
                source="synthetic",
                origin=f"xid:{code}",
            )
        )
    return rows


def gen_failure_mode_rows(failure_modes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each family x symptom -> a row whose annotation embeds the symptom keyword."""
    rows: list[dict[str, Any]] = []
    for entry in failure_modes or []:
        family = str(entry.get("family") or "").strip()
        if not family:
            continue
        alertname = _alertname_for(family)
        for symptom in entry.get("symptoms", []) or []:
            name = str(symptom.get("name") or "").strip()
            keywords = [str(k) for k in (symptom.get("keywords") or []) if str(k).strip()]
            if not name or not keywords:
                continue
            summary = f"{name}: {keywords[0]}"
            annotations = {"summary": summary, "description": "; ".join(keywords[:3])}
            rows.append(
                _row(
                    row_id=f"synthetic:{_slug(family)}-{_slug(name)}",
                    alertname=alertname,
                    labels_extra=_labels_for(family, name),
                    annotations=annotations,
                    expected_family=family,
                    source="synthetic",
                    origin=f"failure_mode:{family}:{name}",
                )
            )
    return rows


def gen_known_issue_rows(known_issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each known issue -> a row for its family (platform_version_bug, etc.)."""
    rows: list[dict[str, Any]] = []
    for entry in known_issues or []:
        family = str(entry.get("family") or "").strip()
        issue = str(entry.get("issue") or "").strip()
        keywords = [str(k) for k in (entry.get("keywords") or []) if str(k).strip()]
        if not family or not issue or not keywords:
            continue
        summary = f"{issue}: {keywords[0]}"
        annotations = {"summary": summary, "description": "; ".join(keywords[:3])}
        affected = str(entry.get("affected_version") or "").strip()
        if affected:
            annotations["description"] += f" (affected {affected})"
        rows.append(
            _row(
                row_id=f"synthetic:known-{_slug(issue)}",
                alertname=_alertname_for(family),
                labels_extra={"namespace": "runai"},
                annotations=annotations,
                expected_family=family,
                source="synthetic",
                origin=f"known_issue:{issue}",
            )
        )
    return rows


def build_synthetic(
    xid_catalog: dict[str, Any],
    failure_modes: list[dict[str, Any]],
    known_issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = gen_xid_rows(xid_catalog) + gen_failure_mode_rows(failure_modes) + gen_known_issue_rows(known_issues)
    return _dedup_by_signature(rows)


# --- confirmed generation (from incidents) -----------------------------------

_LABELED_CASE_TYPES = {"known", "compositional", "tool_degraded"}


def _review_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str) and value.strip():
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _operator_family_label(row: dict[str, Any]) -> tuple[str, list[str]] | None:
    """Return a non-conflicting operator answer key for the active analysis.

    ``evaluation_reviews`` is already hash-scoped by the backend ingest query.
    Novel reviews deliberately have no catalog-family answer. Empty optional
    labels are abstentions, while two distinct explicit labels (or a novel/known
    disagreement) fail closed instead of choosing a reviewer.
    """
    families: set[str] = set()
    case_types: set[str] = set()
    saw_novel = False
    for review in _review_list(row.get("evaluation_reviews")):
        case_type = str(review.get("case_type") or "").strip()
        expected = str(review.get("expected_family") or "").strip()
        if case_type == "novel":
            saw_novel = True
            continue
        if case_type not in _LABELED_CASE_TYPES:
            return None
        if not expected:
            # Scoring-only reviews make no answer-key claim.
            continue
        families.add(expected)
        case_types.add(case_type)
    if saw_novel or len(families) != 1:
        return None
    return next(iter(families)), sorted(case_types)


def build_confirmed(db_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split confirmed incidents into (approved -> curated, pending -> pending).

    Uses the operator-confirmed expected_family and the real incident
    labels/annotations. The model's root_cause_family is retained only as
    diagnostic metadata. Approved = incidents.user_approved_at is set.
    """
    from app.collectors.base import resolve_target
    from ontology import ingest

    approved: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for r in db_rows:
        operator_label = _operator_family_label(r)
        if operator_label is None:
            continue
        family, case_types = operator_label
        labels = ingest._json(r.get("labels"))
        annotations = ingest._json(r.get("annotations"))
        target = resolve_target(labels, annotations)
        alertname = (target.alert_name or "").strip()
        if not alertname or alertname == "RunAIAlert":
            continue
        if not labels.get("alertname"):
            labels = {"alertname": alertname, **labels}
        incident_id = str(r.get("incident_id") or "")
        fingerprint = str(r.get("fingerprint") or "") or _fingerprint(incident_id, family)
        is_approved = bool(str(r.get("user_approved_at") or "").strip())
        row = _row(
            row_id=f"confirmed:{incident_id}",
            alertname=alertname,
            labels_extra={},
            annotations=annotations,
            expected_family=family,
            source="confirmed",
            origin=f"incident:{incident_id}",
            fingerprint=fingerprint,
            extra_meta={
                "approved": is_approved,
                "label_source": "operator_evaluation",
                "case_types": case_types,
                "predicted_family": str(r.get("root_cause_family") or "").strip(),
            },
            labels_override=labels,
        )
        (approved if is_approved else pending).append(row)
    return _dedup_by_signature(approved), _dedup_by_signature(pending)


# --- dedup / merge -----------------------------------------------------------

def _dedup_by_signature(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda r: r["id"]):
        sig = _signature(row)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(row)
    return out


def merge_curated(existing: list[dict[str, Any]], approved_confirmed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Preserve hand rows verbatim + refresh generator-owned confirmed rows.

    Hand rows (meta.source absent or not in _GEN_SOURCES) keep their original
    order. Old generator-owned confirmed rows are dropped and replaced by the
    current approved set, deduped against hand rows by signature so a human row
    always wins.
    """
    kept: list[dict[str, Any]] = []
    hand_sigs: set[tuple[str, str, str]] = set()
    for row in existing:
        source = str(row.get("meta", {}).get("source", ""))
        if source in _GEN_SOURCES:
            continue  # generator-owned; will be regenerated
        kept.append(row)
        hand_sigs.add(_signature(row))
    for row in approved_confirmed:
        if _signature(row) in hand_sigs:
            continue
        kept.append(row)
    return kept


# --- durable dataset store (Postgres) ----------------------------------------

def _dataset_params(row: dict[str, Any]) -> tuple[str, str, str, str, str, str, str, str, bool]:
    """Flatten a generated row into rca_dataset upsert params (pure/testable)."""
    meta = row.get("meta", {})
    alert = row["question"]["alert"]
    origin = str(meta.get("origin", ""))
    incident_id = origin.split("incident:", 1)[1] if origin.startswith("incident:") else ""
    return (
        str(row["id"]),
        str(meta.get("source", "")),
        origin,
        incident_id,
        str(alert.get("labels", {}).get("alertname", "")),
        str(row["answer"]["expected_family"]),
        str(meta.get("label_source", "")),
        json.dumps(row["question"], ensure_ascii=False),
        bool(meta.get("approved", False)),
    )


def _row_from_db(rec: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct a dataset row from an rca_dataset record (pure/testable)."""
    question = rec["question"]
    if isinstance(question, str):
        question = json.loads(question)
    return {
        "id": str(rec["dataset_id"]),
        "question": question,
        "answer": {"expected_family": str(rec.get("expected_family", ""))},
        "meta": {
            "source": str(rec.get("source", "")),
            "origin": str(rec.get("origin", "")),
            "approved": bool(rec.get("approved", False)),
            "label_source": str(rec.get("label_source", "")),
        },
    }


async def _upsert_dataset(
    rows: list[dict[str, Any]], resolved_grace_hours: int = 0
) -> int:
    """Globally reconcile durable labels, then upsert the current incident page.

    Reconciliation is intentionally independent from the fetch limit: a reopened
    historical incident or a corrected old evaluation must retract its measured
    label even when it is no longer in the newest incident page.
    """
    import asyncpg

    from app.config import load_settings

    settings = load_settings()
    if not settings.postgres_dsn:
        print("POSTGRES_DSN not set; skipping dataset store write.")
        return 0
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        await conn.execute(_DATASET_DDL)
        for migration in _DATASET_MIGRATIONS:
            await conn.execute(migration)
        await conn.execute(_DATASET_RECONCILE, max(0, resolved_grace_hours))
        params = [_dataset_params(r) for r in rows]
        if params:
            await conn.executemany(_DATASET_UPSERT, params)
    finally:
        await conn.close()
    return len(rows)


async def _fetch_approved_dataset(
    resolved_grace_hours: int = 0,
) -> list[dict[str, Any]]:
    """Read approved confirmed rows from the durable store for curated export."""
    import asyncpg

    from app.config import load_settings

    settings = load_settings()
    if not settings.postgres_dsn:
        print("POSTGRES_DSN not set; skipping dataset export.")
        return []
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        await conn.execute(_DATASET_DDL)
        for migration in _DATASET_MIGRATIONS:
            await conn.execute(migration)
        await conn.execute(_DATASET_RECONCILE, max(0, resolved_grace_hours))
        recs = await conn.fetch(
            f"SELECT dataset_id, source, origin, expected_family, label_source, question, approved "
            f"FROM {DATASET_TABLE} WHERE approved = true "
            f"AND label_source = 'operator_evaluation' ORDER BY dataset_id"
        )
    finally:
        await conn.close()
    return [_row_from_db(dict(r)) for r in recs]


# --- IO ----------------------------------------------------------------------

def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            # Compact separators match the hand-authored curated file byte-for-byte,
            # so re-running the generator never churns whitespace in git diffs.
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _load_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# --- orchestration -----------------------------------------------------------

def run(
    *,
    from_ontology: bool,
    from_incidents: bool,
    export_curated: bool,
    knowledge_dir: Path,
    eval_dir: Path,
    limit: int,
    resolved_grace_hours: int,
    dry_run: bool,
) -> dict[str, int]:
    counts: dict[str, int] = {}

    if from_ontology:
        xid = _load_yaml(knowledge_dir / "xid_catalog.yaml") or {}
        failure_modes = _load_yaml(knowledge_dir / "failure_modes.yaml") or []
        known_issues = _load_yaml(knowledge_dir / "runai_known_issues.yaml") or []
        synthetic = build_synthetic(xid, failure_modes, known_issues)
        counts["synthetic"] = len(synthetic)
        if not dry_run:
            _write_jsonl(eval_dir / SYNTHETIC_FILE, synthetic)

    if from_incidents:
        from ontology import ingest

        db_rows = asyncio.run(ingest._fetch(limit, resolved_grace_hours))
        approved, pending = build_confirmed(db_rows)
        counts["confirmed_approved"] = len(approved)
        counts["confirmed_pending"] = len(pending)
        if not dry_run:
            # Durable accumulation: both approved and pending operator-labeled
            # rows live in rca_dataset; approval drives curated export.
            counts["dataset_upserted"] = asyncio.run(
                _upsert_dataset(approved + pending, resolved_grace_hours)
            )

    if export_curated:
        approved_rows = asyncio.run(
            _fetch_approved_dataset(resolved_grace_hours)
        )
        existing = _read_jsonl(eval_dir / CURATED_FILE)
        merged = merge_curated(existing, approved_rows)
        counts["curated"] = len(merged)
        if not dry_run:
            _write_jsonl(eval_dir / CURATED_FILE, merged)

    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the RCA family-classification dataset.")
    parser.add_argument("--from-ontology", action="store_true", help="regenerate the synthetic regression file from knowledge/*.yaml")
    parser.add_argument("--from-incidents", action="store_true", help="accumulate operator-labeled incident rows into the rca_dataset store")
    parser.add_argument("--export-curated", action="store_true", help="materialize approved rows from rca_dataset into the curated nat_dataset.jsonl (preserving hand rows)")
    parser.add_argument("--knowledge-dir", default=str(_KNOWLEDGE_DIR), help="directory holding the knowledge *.yaml catalogs")
    parser.add_argument("--eval-dir", default=str(_EVAL_DIR), help="directory holding the dataset *.jsonl files")
    parser.add_argument("--limit", type=int, default=500, help="max incidents to scan (--from-incidents)")
    parser.add_argument("--resolved-grace-hours", type=int, default=0, help="only confirmed incidents resolved at least N hours ago (0 = no gate)")
    parser.add_argument("--dry-run", action="store_true", help="print counts without writing files or the dataset store")
    args = parser.parse_args(argv)

    if not args.from_ontology and not args.from_incidents and not args.export_curated:
        args.from_ontology = True
        args.from_incidents = True

    counts = run(
        from_ontology=args.from_ontology,
        from_incidents=args.from_incidents,
        export_curated=args.export_curated,
        knowledge_dir=Path(args.knowledge_dir),
        eval_dir=Path(args.eval_dir),
        limit=args.limit,
        resolved_grace_hours=args.resolved_grace_hours,
        dry_run=args.dry_run,
    )
    prefix = "[dry-run] " if args.dry_run else ""
    print(f"{prefix}gen_dataset: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
