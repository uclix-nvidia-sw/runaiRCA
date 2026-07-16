"""Load external NVIDIA support-case payloads into TypeDB as LABELLED priors.

Consumes each curated bundle's ``03_ingestion_payload.yaml`` (schema v2.0,
``payload_kind: historical_incident_candidate``). These are external,
curator-approved cases whose payloads self-declare
``eligible_for_positive_promotion: false``. They are ingested ONLY as retrieval
context — a ``case_snapshot`` + ``diagnosis`` + ``evidence`` + one case-local
``symptom`` — never as knowledge-layer authority. This loader structurally never
writes ``indicates``/``resolved_by`` edges, so ``_KNOWLEDGE_QUERY`` (which
requires both) can never surface them; retrieval is via error-signature match on
the case-local symptom keywords (see app/services/kg_enrichment.py).

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \
        ./.venv/bin/python -m ontology.load_external_cases \
        --approved-by "<operator>" [--cases <case-suffix>,...]

Committed payloads are DE-IDENTIFIED by knowledge/external_cases/sanitize.py
(no support-case numbers anywhere); case ids look like enterprise_support:<hash>.

``--dry-run`` maps every payload and prints a summary WITHOUT touching TypeDB, so
the mapping can be reviewed before any write. Run from ``agent/`` so the relative
``knowledge/families.yaml`` path inside ingest resolves.

ponytail: all TypeQL is delegated to the proven ingest / load_knowledge helpers
(``_write_incident``, ``_ensure_symptom``, ``_relate``); this module adds no new
insert syntax. First real load needs live TypeDB validation — TypeQL 3.x is not
exercised by the unit tests.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.config import load_settings
from app.services.root_cause_ranking import novel_family_slug
from ontology import ingest
from ontology.incident import OntologyIncident
from ontology.load_knowledge import _ensure_symptom

PAYLOAD_NAME = "03_ingestion_payload.yaml"
# Baked into the agent image (agent/Dockerfile COPYs knowledge/); the Helm
# schema-load job runs from /app so this relative default resolves, matching the
# env-driven path convention of the other ontology loaders.
_DEFAULT_DIR = os.getenv("EXTERNAL_CASES_DIR", "knowledge/external_cases")
_SCHEMA_VERSION = "2.0"
_KIND = "historical_incident_candidate"
_CONTEXT_CLASSES = {"evaluation_only", "mitigated_context", "unresolved_context"}

# Payload action outcomes → the three the graph's `resolution` relation accepts
# (ingest._ensure_resolution silently drops anything else). Successful outcomes
# feed successful_actions; ineffective feeds failed_actions. diagnostic /
# preventive / unknown_outcome are deliberately NOT resolutions of THIS incident
# — they live only in the stored case_card historical_actions.
_SUCCESS_OUTCOME = {
    "resolving": "resolved",
    "mitigating": "mitigated",
    "partially_effective": "mitigated",
}
_FAILED_OUTCOME = {"ineffective": "ineffective"}
_MAX_KEYWORDS = 12


def _find_payloads(paths: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in paths:
        base = Path(raw)
        if base.is_file() and base.name == PAYLOAD_NAME:
            found.append(base)
        else:
            found.extend(sorted(base.rglob(PAYLOAD_NAME)))
    # dedupe by resolved path, keep order
    seen: set[Path] = set()
    unique: list[Path] = []
    for p in found:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            unique.append(p)
    return unique


def _validate(payload: dict[str, Any]) -> str:
    """Return "" if ingestible, else a human-readable skip reason."""
    if str(payload.get("payload_schema_version") or "") != _SCHEMA_VERSION:
        return f"unsupported payload_schema_version {payload.get('payload_schema_version')!r}"
    if str(payload.get("payload_kind") or "") != _KIND:
        return f"unsupported payload_kind {payload.get('payload_kind')!r}"
    if not str((payload.get("identity") or {}).get("deduplication_key") or ""):
        return "missing identity.deduplication_key"
    decision = str((payload.get("approval") or {}).get("curation_decision") or "")
    if not decision.startswith("approved_for_ingestion"):
        return f"curation_decision not approved ({decision!r})"
    ctx = str((payload.get("historical_use") or {}).get("context_class") or "")
    if ctx not in _CONTEXT_CLASSES:
        return f"unexpected context_class {ctx!r}"
    if not str((payload.get("incident") or {}).get("family") or ""):
        return "missing incident.family"
    return ""


def _confidence_bucket(value: Any) -> str:
    """low|medium|high. Pass valid strings through; bucket numeric confidences."""
    text = str(value or "").strip().lower()
    if text in {"low", "medium", "high"}:
        return text
    try:
        num = float(value)
    except (TypeError, ValueError):
        return "low"
    return "high" if num >= 0.8 else "medium" if num >= 0.5 else "low"


def _case_number(dedup_key: str) -> str:
    """`enterprise_support:<hash>` -> `<hash>` (the opaque case-id suffix)."""
    return dedup_key.rsplit(":", 1)[-1].strip()


def _ext_ids(payload: dict[str, Any]) -> tuple[str, str]:
    """Return (case_id, incident_id). incident_id == run_id."""
    dedup = str((payload.get("identity") or {}).get("deduplication_key") or "")
    return dedup, f"ext:sc-{_case_number(dedup)}"


def _actions(payload: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Split historical_actions into graph-writable successful/failed lists."""
    successful: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    for act in payload.get("historical_actions") or []:
        statement = str(act.get("normalized_action") or "").strip()
        outcome = str(act.get("outcome") or "").strip()
        if not statement:
            continue
        if outcome in _SUCCESS_OUTCOME:
            successful.append({"statement": statement, "outcome": _SUCCESS_OUTCOME[outcome]})
        elif outcome in _FAILED_OUTCOME:
            failed.append({"statement": statement, "outcome": _FAILED_OUTCOME[outcome]})
    return successful, failed


def _supporting_evidence_ids(payload: dict[str, Any]) -> list[str]:
    """Evidence ids backing a successful action: the action's own evidence_ids
    ∪ evidence_refs whose `supports` names that action. Unresolved cases (no
    successful action) yield [] → no supported_by edge, by design."""
    success_ids = {
        str(a.get("action_id") or "")
        for a in payload.get("historical_actions") or []
        if str(a.get("outcome") or "").strip() in _SUCCESS_OUTCOME and a.get("action_id")
    }
    if not success_ids:
        return []
    ids: set[str] = set()
    for a in payload.get("historical_actions") or []:
        if str(a.get("action_id") or "") in success_ids:
            ids.update(str(e) for e in (a.get("evidence_ids") or []))
    for e in payload.get("evidence_refs") or []:
        if success_ids.intersection(str(s) for s in (e.get("supports") or [])):
            ids.add(str(e.get("evidence_id") or ""))
    return sorted(i for i in ids if i)


def _clean_keyword(sig: Any) -> str:
    """Strip a trailing curator annotation like `(reported, raw log unavailable)`
    (which would never appear in a real log, so it's a dead keyword) and collapse
    whitespace. Salvages the real signal preceding the annotation."""
    text = re.sub(
        r"\s*\([^)]*(?:reported|unavailable)[^)]*\)\s*$", "", str(sig), flags=re.IGNORECASE
    )
    return " ".join(text.split())


def _is_generic(token: str) -> bool:
    """A bare single word with no code-like marker (oomkilled, nfs, git)
    over-matches unrelated evidence. Multi-word error phrases and tokens with a
    digit or `_ : / . = -` are specific enough to keep."""
    return " " not in token and not any(c.isdigit() or c in "_:/.=-" for c in token)


def _symptom_keywords(payload: dict[str, Any]) -> list[str]:
    """Case-local symptom keywords = error_signatures plus any
    curated_signature_tokens the sanitizer injected for cases that have no error
    string (cleaned, generic dropped, lowercased, deduped, capped).
    normalized_symptoms/retrieval_keywords are prose — never used; the owner's
    retrieval entry point is the error string."""
    context = payload.get("searchable_context") or {}
    sigs = list(context.get("error_signatures") or []) + list(
        context.get("curated_signature_tokens") or []
    )
    out: list[str] = []
    seen: set[str] = set()
    for sig in sigs:
        cleaned = _clean_keyword(sig)
        if not cleaned or _is_generic(cleaned):
            continue
        kw = cleaned.lower()
        if kw not in seen:
            seen.add(kw)
            out.append(kw)
        if len(out) >= _MAX_KEYWORDS:
            break
    return out


def _to_incident(
    payload: dict[str, Any], approved_by: str, approved_at: str
) -> OntologyIncident:
    identity = payload.get("identity") or {}
    inc_data = payload.get("incident") or {}
    hist = payload.get("historical_use") or {}
    case_id, incident_id = _ext_ids(payload)

    confirmed = str(inc_data.get("confirmed_mechanism") or "").strip()
    observed = str(inc_data.get("observed_mechanism") or "").strip()
    mechanism = confirmed or (f"unconfirmed: {observed}" if observed else "")
    fingerprint = novel_family_slug(mechanism)[1] if mechanism else ""

    successful, failed = _actions(payload)
    status = str(inc_data.get("status") or "unresolved").strip()

    artifacts = [
        {
            "evidence_id": str(e.get("evidence_id") or ""),
            "source": str(e.get("source_actor") or "external"),
            "type": str(e.get("evidence_kind") or "statement"),
            "summary": str(e.get("masked_summary") or ""),
            "confidence": "low",
        }
        for e in payload.get("evidence_refs") or []
        if e.get("evidence_id")
    ]

    harness = {
        "status": "external",
        "diagnosis_state": status,
        "overall_score": 0,
        "claims": [
            {
                "kind": "root_cause",
                "confidence": _confidence_bucket(inc_data.get("family_confidence")),
                "supporting_evidence": _supporting_evidence_ids(payload),
            }
        ],
    }

    # Stored case_card. ingest._case_card_for_graph stamps historical_prior/
    # case_id/family/mechanism/successful+failed_actions on top of this; only
    # incident_status_at_approval sits under `context` (the only whitelisted
    # context field). Component/version tokens stay in searchable_context so the
    # env-compatibility filter never keys off a foreign entity name.
    case_card = {
        "case_origin": str(identity.get("source_system") or "enterprise_support"),
        "context_class": str(hist.get("context_class") or ""),
        "allowed_uses": list(hist.get("allowed_uses") or []),
        "prohibited_uses": list(hist.get("prohibited_uses") or []),
        "source_revision_hash": str(identity.get("source_revision_hash") or ""),
        "curation_revision": identity.get("curation_revision"),
        "occurred_at": str(inc_data.get("occurred_at") or ""),
        "mechanism_confirmed": bool(confirmed),
        "approved_by": approved_by,
        "searchable_context": payload.get("searchable_context") or {},
        "historical_actions": payload.get("historical_actions") or [],
        "context": {"incident_status_at_approval": status},
    }

    return OntologyIncident(
        incident_id=incident_id,
        run_id=incident_id,
        case_id=case_id,
        analysis_hash=str(identity.get("source_revision_hash") or ""),
        approval_state="active",
        user_approved_at=approved_at,
        mechanism=mechanism,
        mechanism_fingerprint=fingerprint,
        title=str(inc_data.get("title") or ""),
        severity="warning",
        status=status,
        analysis_summary=str(inc_data.get("masked_summary") or ""),
        root_cause_family=str(inc_data.get("family") or ""),
        artifacts=artifacts,
        harness=harness,
        successful_actions=successful,
        failed_actions=failed,
        case_card=case_card,
    )


def _write_case(tx: Any, inc: OntologyIncident, keywords: list[str]) -> None:
    """Write one case's incident projection + case-local symptom + has_symptom
    edge. NEVER calls _relate_indicates / _relate_resolved_by — that structural
    omission is the knowledge-layer isolation guarantee (see module docstring)."""
    ingest._write_incident(tx, inc)
    if keywords:
        _ensure_symptom(tx, inc.incident_id, keywords)
        ingest._relate(
            tx,
            ("incident", "incident_id", inc.incident_id),
            ("symptom", "name", inc.incident_id),
            "has_symptom", "incident", "symptom",
        )


def _write_external(cases: list[tuple[OntologyIncident, list[str]]]) -> tuple[int, int]:
    """One WRITE txn per case (mirrors ingest._write); commits per case so a bad
    row can't drop the batch."""
    from typedb.driver import TransactionType

    from app.ontology.typedb_client import open_driver

    settings = load_settings()
    written = failed = 0
    with open_driver(settings) as driver:
        for inc, keywords in cases:
            try:
                with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
                    _write_case(tx, inc, keywords)
                    tx.commit()
                written += 1
            except Exception as exc:  # noqa: BLE001 - report and continue the batch
                failed += 1
                print(f"  ! {inc.incident_id}: {type(exc).__name__}: {exc}", file=sys.stderr)
    return written, failed


def _summary_row(inc: OntologyIncident, payload: dict[str, Any], keywords: list[str]) -> str:
    graph_actions = len(inc.successful_actions) + len(inc.failed_actions)
    excluded = len(payload.get("historical_actions") or []) - graph_actions
    support = len(inc.harness["claims"][0]["supporting_evidence"])
    mech = "confirmed" if inc.case_card["mechanism_confirmed"] else "UNCONFIRMED"
    return (
        f"{inc.incident_id:<16} {inc.root_cause_family:<24} {inc.status:<12} "
        f"{inc.case_card['context_class']:<18} mech={mech:<11} "
        f"act=+{len(inc.successful_actions)}/-{len(inc.failed_actions)}/~{excluded} "
        f"ev={len(inc.artifacts)}(sup={support}) kw={len(keywords)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Load external NVIDIA support-case payloads (v2.0) as labelled priors."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help=f"dirs or payload files to scan for {PAYLOAD_NAME} (default: {_DEFAULT_DIR})",
    )
    parser.add_argument(
        "--approved-by",
        default="",
        help="operator binding the case-level approval (required unless --dry-run)",
    )
    parser.add_argument(
        "--cases", default="", help="comma-separated case-id suffix filter (the hash after ':')"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="map and print a summary without touching TypeDB"
    )
    args = parser.parse_args()

    case_filter = {c.strip() for c in args.cases.split(",") if c.strip()}
    if not args.dry_run and not args.approved_by.strip():
        print("--approved-by is required unless --dry-run (binds approval).", file=sys.stderr)
        return 2

    paths = args.paths or [_DEFAULT_DIR]
    approved_at = datetime.now().astimezone().isoformat()
    prepared: list[tuple[OntologyIncident, dict[str, Any], list[str]]] = []
    seen_cases: set[str] = set()
    for path in _find_payloads(paths):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:  # warning-only: bad file, keep going
            print(f"  ! {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        reason = _validate(payload)
        if reason:
            print(f"  skip {path.name} ({path.parent.name}): {reason}", file=sys.stderr)
            continue
        case_id, incident_id = _ext_ids(payload)
        if case_filter and _case_number(case_id) not in case_filter:
            continue
        if case_id in seen_cases:
            print(f"  skip duplicate case_id {case_id} ({path})", file=sys.stderr)
            continue
        seen_cases.add(case_id)
        inc = _to_incident(payload, args.approved_by.strip(), approved_at)
        prepared.append((inc, payload, _symptom_keywords(payload)))

    print(f"prepared {len(prepared)} case(s)")
    print("  legend: act=+ok/-failed/~excluded  ev=evidence(sup=supported_by)  kw=keywords\n")
    for inc, payload, keywords in prepared:
        print("  " + _summary_row(inc, payload, keywords))
        if keywords:
            print(f"      keywords: {keywords}")
        else:
            rk = (payload.get("searchable_context") or {}).get("retrieval_keywords") or []
            print(
                "      keywords: NONE (no error_signatures) — not signature-retrievable; "
                f"retrieval_keywords available: {len(rk)}"
            )

    if args.dry_run:
        print("\ndry-run: no TypeDB writes.")
        return 0

    if not prepared:
        return 0  # nothing injected (e.g. an open-source build) — clean no-op

    if not load_settings().enable_typedb:
        print("ENABLE_TYPEDB is not set; nothing written.", file=sys.stderr)
        return 0

    written, failed = _write_external([(inc, kw) for inc, _payload, kw in prepared])
    print(f"done: {written} written, {failed} failed")
    return 1 if failed and not written else 0


if __name__ == "__main__":
    raise SystemExit(main())
