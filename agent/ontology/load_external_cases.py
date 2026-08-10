"""Load external NVIDIA support-case payloads into TypeDB as TRUSTED knowledge.

Consumes each curated bundle's ``03_ingestion_payload.yaml`` (schema v2.0,
``payload_kind: historical_incident_candidate``). Owner decision 2026-07-27:
these are vendor-support threads — trusted, so they enter the SAME
family→symptom→action chain as curated knowledge (``indicates`` for the
closed-catalog family, ``resolved_by`` for support-confirmed actions), which
puts them on every knowledge surface: ``_KNOWLEDGE_QUERY`` → signature
matching, the plan-time symptom lead, guidance and actions. Their
diagnostic/preventive support-thread steps additionally become a per-case
mini-runbook of ``diagnostic_step`` entities (never wired into the main
executable walk — runbook-name scoping keeps walk_tree on the bundled tree).
Error-signature retrieval on the ``ext:`` symptom keywords is unchanged.

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
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import load_settings
from app.services.root_cause_ranking import novel_family_slug
from ontology import ingest
from ontology.incident import OntologyIncident
from ontology.load_knowledge import (
    FAMILIES,
    _ensure_symptom,
)
from ontology.normalization import confidence_score
from ontology.upsert import (
    ensure_action,
    relate_symptom_indicates,
    relate_symptom_resolved_by,
)

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
    if confidence_score(text) is not None:
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
    whitespace. Salvages the real signal preceding the annotation.

    Signatures the sanitizer masked in place — `nfs: server <address> not
    responding, still trying` — can never substring-match real text (real logs
    carry an actual IP/hostname where the placeholder sits), so the whole
    keyword was dead. Keep the longest literal fragment around the placeholder
    instead; the generic-token gate downstream still applies to the salvage."""
    text = re.sub(
        r"\s*\([^)]*(?:reported|unavailable)[^)]*\)\s*$", "", str(sig), flags=re.IGNORECASE
    )
    if re.search(r"<[^<>]{1,40}>", text):
        fragments = [
            fragment.strip(" \t:,-") for fragment in re.split(r"<[^<>]{1,40}>", text)
        ]
        text = max(fragments, key=len, default="")
    return " ".join(text.split())


def _is_generic(token: str) -> bool:
    """A bare single word with no code-like marker (oomkilled, nfs, git)
    over-matches unrelated evidence. Multi-word error phrases and tokens with a
    digit or `_ : / . = -` are specific enough to keep."""
    return " " not in token and not any(c.isdigit() or c in "_:/.=-" for c in token)


def _symptom_keywords(payload: dict[str, Any]) -> list[str]:
    """Case-local symptom keywords = error_signatures plus any
    curated_signature_tokens the sanitizer injected for cases that have no error
    string, plus canonical_component_tokens, trigger_tokens, metric_signatures,
    and issue_references (cleaned, generic dropped, lowercased, deduped,
    capped). Component tokens are exact hyphenated names
    (runai-backend-thanos-receive) that appear verbatim in pod-name evidence —
    they give a case whose only error signature is a rare log line a reachable
    entry point once the component is targeted. trigger_tokens/
    metric_signatures/issue_references are the curator's own specific
    signatures (PromQL fragments, external bug-tracker IDs, named trigger
    conditions) — without them a case whose only distinguishing signal is a
    metric or trigger token was unretrievable. normalized_symptoms/
    retrieval_keywords/version_tokens are prose — never used; the owner's
    retrieval entry points are the error string and canonical identifiers,
    never prose."""
    context = payload.get("searchable_context") or {}
    sigs = (
        list(context.get("error_signatures") or [])
        + list(context.get("curated_signature_tokens") or [])
        + list(context.get("canonical_component_tokens") or [])
        + list(context.get("trigger_tokens") or [])
        + list(context.get("metric_signatures") or [])
        + list(context.get("issue_references") or [])
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


def _family_candidates(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Curated differential diagnosis (``knowledge_links.family_candidates``):
    other plausible families the curator weighed against the one asserted
    ``indicates`` edge, each with a confidence bucket. Bounded to the closed
    family catalog so an unrecognized name never reaches a consumer."""
    links = payload.get("knowledge_links") or {}
    out: list[dict[str, str]] = []
    for item in links.get("family_candidates") or []:
        if not isinstance(item, dict):
            continue
        family = str(item.get("family") or "").strip()
        if family not in FAMILIES:
            continue
        out.append({"family": family, "confidence": _confidence_bucket(item.get("confidence"))})
    return out[:5]


@lru_cache(maxsize=1)
def _closed_symptom_names() -> frozenset[str]:
    """Curated failure-mode symptom names (knowledge/failure_modes.yaml) — the
    closed catalog `_knowledge_links_matches` validates a curator's free-text
    `failure_mode_matches` citation against, same role FAMILIES plays for
    family_candidates above."""
    try:
        raw = yaml.safe_load(
            Path(load_settings().failure_modes_file).read_text(encoding="utf-8")
        ) or []
    except (OSError, yaml.YAMLError):
        return frozenset()
    return frozenset(
        name
        for family in raw
        if isinstance(family, dict)
        for symptom in family.get("symptoms") or []
        if isinstance(symptom, dict) and (name := str(symptom.get("name") or "").strip())
    )


@lru_cache(maxsize=1)
def _closed_known_issue_names() -> frozenset[str]:
    """Known-issue names (knowledge/runai_known_issues.yaml `issue:`) — the
    closed catalog `_knowledge_links_matches` validates a curator's free-text
    `known_issue_matches` citation against."""
    try:
        raw = yaml.safe_load(
            Path(load_settings().runai_known_issues_file).read_text(encoding="utf-8")
        ) or []
    except (OSError, yaml.YAMLError):
        return frozenset()
    return frozenset(
        name
        for entry in raw
        if isinstance(entry, dict) and (name := str(entry.get("issue") or "").strip())
    )


def _knowledge_links_matches(
    payload: dict[str, Any], link_key: str, valid_names: frozenset[str]
) -> list[dict[str, str]]:
    """Curator cross-references (``knowledge_links.failure_mode_matches`` /
    ``known_issue_matches``): this external case's mechanism overlaps an
    EXISTING catalog entry, so the report can cite the more precise curated
    fix instead of only the raw external case.

    Dict-shaped entries only, and only when the name exact-matches the closed
    catalog: a prior pass wired family_candidates and explicitly left these two
    unwired because they name free-text catalog entries needing sanitisation.
    A bare string entry (curator prose, e.g. "X — partial match because...")
    has no separable name field safe to validate, so it is skipped rather than
    parsed; that also correctly drops a "no existing entry" sentinel like
    ``{"status": "none", "candidate_name": ...}``, which never carries a
    `catalog_entry`/`repository_entry`/`issue` key at all.
    """
    links = payload.get("knowledge_links") or {}
    out: list[dict[str, str]] = []
    for item in links.get(link_key) or []:
        if not isinstance(item, dict):
            continue
        name = str(
            item.get("catalog_entry") or item.get("repository_entry") or item.get("issue") or ""
        ).strip()
        if name not in valid_names:
            continue
        entry = {"name": name, "confidence": _confidence_bucket(item.get("confidence"))}
        if match_type := str(item.get("match_type") or "").strip():
            entry["match_type"] = match_type
        out.append(entry)
    return out[:5]


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
        # Bounded evidence projection so a hint can say what an action found,
        # not just what it was. No `supports`/`source_message_ids`: those name
        # F00x/H00x/M00x ids that are never shipped in this payload.
        "evidence_refs": [
            {
                "evidence_id": str(e.get("evidence_id") or ""),
                "source": str(e.get("source_actor") or "external"),
                "kind": str(e.get("evidence_kind") or "statement"),
                "summary": " ".join(str(e.get("masked_summary") or "").split())[:240],
            }
            for e in payload.get("evidence_refs") or []
            if e.get("evidence_id")
        ],
        "context": {"incident_status_at_approval": status},
        "family_candidates": _family_candidates(payload),
        "failure_mode_matches": _knowledge_links_matches(
            payload, "failure_mode_matches", _closed_symptom_names()
        ),
        "known_issue_matches": _knowledge_links_matches(
            payload, "known_issue_matches", _closed_known_issue_names()
        ),
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


def _write_case(
    tx: Any,
    inc: OntologyIncident,
    keywords: list[str],
    identity_tokens: frozenset[str] = frozenset(),
) -> None:
    """Write one case's incident projection + its ``ext:`` symptom, wired into
    the SAME family→symptom→action chain as curated knowledge.

    Owner decision 2026-07-27: vendor-support cases are TRUSTED knowledge — the
    earlier case-local isolation (no indicates/resolved_by edges) kept them out
    of _KNOWLEDGE_QUERY, so they never reached signature matching, the plan-time
    symptom lead, guidance, or actions. The chain is still honest about what it
    asserts: indicates only for a closed-catalog family, resolved_by only for
    actions the support thread confirmed (resolving/mitigating outcomes —
    diagnostic/preventive steps remain investigation hints on the case card).
    The ``ext:`` symptom name keeps provenance visible in the graph and in any
    report line citing it; ``reason`` carries the confirmed mechanism."""
    ingest._write_incident(tx, inc)
    if not keywords:
        return
    # Trust guards (owner-approved 2026-07-27). The chain asserts causality, so
    # it must respect the CURATOR's own judgement and only match on signatures
    # specific enough to name this case:
    #   1. A case whose support thread never CONFIRMED the mechanism
    #      (mechanism_confirmed=false — observed-only), stays retrieval+playbook.
    #      NOTE: the prohibited_uses "positive_promotion" label is deliberately
    #      NOT a gate — every shipped payload carries it as a blanket
    #      sanitizer-era declaration from the old isolation design, so honoring
    #      it would zero the chain and silently revert the owner's 2026-07-27
    #      trust decision. A per-case opt-out belongs in a dedicated field.
    #   2. Only specific signatures may anchor the chain symptom: multi-word
    #      phrases, long tokens, or code-ish identifiers. A single generic word
    #      ("oomkilled") would substring-match every unrelated OOM incident.
    #      When no keyword survives the gate, the case demotes to retrieval-only
    #      with its full keyword set instead of entering the chain unanchored.
    #   3. canonical_component_tokens (identity_tokens) never anchor the chain,
    #      no matter how long or hyphenated they are — a component name says
    #      WHO was touched, not WHAT broke. They stay in the retrieval-only
    #      keyword set (below) so a demoted or non-chain case can still be
    #      found via them.
    chain = (
        inc.root_cause_family in FAMILIES
        and bool(inc.case_card.get("mechanism_confirmed"))
    )
    chain_keywords = (
        [kw for kw in keywords if kw not in identity_tokens and _chain_specific(kw)]
        if chain
        else []
    )
    if chain and not chain_keywords:
        chain = False
    _ensure_symptom(
        tx,
        inc.incident_id,
        chain_keywords if chain else keywords,
        reason=inc.mechanism,
    )
    ingest._relate(
        tx,
        ("incident", "incident_id", inc.incident_id),
        ("symptom", "name", inc.incident_id),
        "has_symptom", "incident", "symptom",
    )
    if chain:
        relate_symptom_indicates(tx, inc.incident_id, inc.root_cause_family)
        for action in inc.successful_actions:
            statement = str(action.get("statement") or "").strip()
            if not statement:
                continue
            ensure_action(tx, statement)
            relate_symptom_resolved_by(tx, inc.incident_id, statement)
    else:
        # A case demoted AFTER previously entering the chain must lose its old
        # causal edges (its keywords self-reconcile inside _ensure_symptom).
        _delete_chain_edges(tx, inc.incident_id)
    _write_diagnostic_playbook(tx, inc)


def _delete_chain_edges(tx: Any, symptom_name: str) -> None:
    from app.ontology.typedb_client import escape_typeql as esc

    for relation, role in (("indicates", "symptom"), ("resolved_by", "symptom")):
        tx.query(
            f'match $s isa symptom, has name "{esc(symptom_name)}"; '
            f"$x isa {relation}({role}: $s); delete $x;"
        ).resolve()


def _chain_specific(keyword: str) -> bool:
    """Specific enough to anchor a causal match: a multi-word phrase, a long
    token, or a code-ish identifier (runai_pod_gpu_info, error: column …)."""
    keyword = keyword.strip()
    return " " in keyword or len(keyword) >= 12 or any(c in keyword for c in "_:./")


def _component_identity_tokens(payload: dict[str, Any]) -> frozenset[str]:
    """The subset of ``_symptom_keywords`` sourced from canonical_component_tokens
    — cleaned/lowercased the same way, so the strings compare equal.

    A component name (gpu-operator, runai-scheduler-default, ...) identifies
    WHICH pod/product an incident touched, never WHAT went wrong; it says
    nothing that ``_chain_specific``'s length/shape heuristic can see (these
    names are routinely long and hyphenated, so they pass it). Identity is
    provenance, not shape — the loader must track it by source, not guess it
    back from the string. Legitimate for retrieval (kept in _symptom_keywords'
    output); excluded from _write_case's causal chain_keywords."""
    context = payload.get("searchable_context") or {}
    out: set[str] = set()
    for token in context.get("canonical_component_tokens") or []:
        cleaned = _clean_keyword(token)
        if cleaned:
            out.add(cleaned.lower())
    return frozenset(out)


_PLAYBOOK_STEP_OUTCOMES = ("diagnostic", "preventive")


def _delete_playbook(tx: Any, incident_id: str) -> None:
    from app.ontology.typedb_client import escape_typeql as esc

    name = esc(f"{incident_id}:playbook")
    tx.query(
        f'match $s isa diagnostic_step, has runbook_name "{name}"; '
        f"$x isa diagnostic_transition(prior: $s); delete $x;"
    ).resolve()
    for relation in ("runbook_entry", "runbook_contains"):
        tx.query(
            f'match $r isa runbook, has name "{name}"; '
            f"$x isa {relation}(runbook: $r); delete $x;"
        ).resolve()
    tx.query(f'match $x isa diagnostic_step, has runbook_name "{name}"; delete $x;').resolve()
    tx.query(f'match $x isa runbook, has name "{name}"; delete $x;').resolve()


def _delete_case_surfaces(tx: Any, incident_id: str) -> None:
    """Remove a vanished case's ACTIVE surfaces: chain edges, symptom, playbook.

    The historical incident/case_snapshot projection stays — it is archive, not
    a matcher. Used by the sweep for cases no longer shipped in the repo, so a
    bad case removed from git actually leaves the runtime knowledge."""
    from app.ontology.typedb_client import escape_typeql as esc

    _delete_chain_edges(tx, incident_id)
    tx.query(
        f'match $s isa symptom, has name "{esc(incident_id)}"; '
        f"$x isa has_symptom(symptom: $s); delete $x;"
    ).resolve()
    tx.query(f'match $s isa symptom, has name "{esc(incident_id)}"; delete $s;').resolve()
    _delete_playbook(tx, incident_id)


def _sweep_missing_cases(settings: Any, keep_ids: set[str]) -> tuple[list[str], list[str]]:
    """Best-effort removal of graph cases the repo no longer ships.

    Reads every ``ext:`` symptom name, diffs against the loaded set, and deletes
    the missing ones' surfaces case-by-case. Every step is non-fatal: a read or
    per-case failure prints a warning and moves on — sweeping must never block
    loading."""
    from typedb.driver import TransactionType

    from app.ontology.typedb_client import TypeDBClient, open_driver

    try:
        with TypeDBClient(settings).open_reader() as run:
            names = {
                str(row.get("n") or "")
                for row in run('match $s isa symptom, has name $n; $n like "ext:.*"; select $n;')
            }
    except Exception as exc:  # noqa: BLE001 - sweep is advisory
        print(f"  ! sweep skipped (read failed): {type(exc).__name__}: {exc}", file=sys.stderr)
        return [], []
    missing = sorted(name for name in names if name and name not in keep_ids)
    removed: list[str] = []
    failed: list[str] = []
    if not missing:
        return removed, failed
    with open_driver(settings) as driver:
        for incident_id in missing:
            try:
                with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
                    _delete_case_surfaces(tx, incident_id)
                    tx.commit()
                removed.append(incident_id)
            except Exception as exc:  # noqa: BLE001 - keep sweeping the rest
                failed.append(incident_id)
                print(f"  ! sweep {incident_id}: {type(exc).__name__}: {exc}", file=sys.stderr)
    return removed, failed


def _write_diagnostic_playbook(tx: Any, inc: OntologyIncident) -> None:
    """Mirror the support thread's diagnostic/preventive steps one-by-one as a
    per-case mini-runbook of ``diagnostic_step`` entities.

    These are the commands/checks actually exchanged with vendor support —
    valuable as an ordered sequence, not as resolved_by fixes. The runbook name
    is case-scoped (``<case>:playbook``) so the executable walk, which loads
    steps by the bundled runbook's name, never routes into them. Replace-in-full
    per case: rerunning the loader must not duplicate steps."""
    from app.ontology.typedb_client import escape_typeql as esc

    leads = [
        str(action.get("normalized_action") or "").strip()
        for action in inc.case_card.get("historical_actions") or []
        if str(action.get("outcome") or "").strip() in _PLAYBOOK_STEP_OUTCOMES
        and str(action.get("normalized_action") or "").strip()
    ]
    runbook_name = f"{inc.incident_id}:playbook"
    name = esc(runbook_name)
    _delete_playbook(tx, inc.incident_id)
    if not leads:
        return
    summary = f"Vendor-support diagnostic sequence for {inc.incident_id} ({len(leads)} steps)"
    tx.query(
        f'insert $x isa runbook, has name "{name}", has summary "{esc(summary)}";'
    ).resolve()
    previous = ""
    for index, statement in enumerate(leads, start=1):
        step_id = f"{inc.incident_id}:d{index:02d}"
        tx.query(
            f'insert $x isa diagnostic_step, has diagnostic_id "{esc(step_id)}", '
            f'has runbook_name "{name}", has question "{esc(statement)}", '
            f'has verification "", has interpretation "", has avoidance "", '
            f'has match_expression "";'
        ).resolve()
        tx.query(
            f'match $r isa runbook, has name "{name}"; '
            f'$s isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
            f"insert (runbook: $r, step: $s) isa runbook_contains;"
        ).resolve()
        if index == 1:
            tx.query(
                f'match $r isa runbook, has name "{name}"; '
                f'$s isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
                f"insert (runbook: $r, step: $s) isa runbook_entry;"
            ).resolve()
        if previous:
            tx.query(
                f'match $p isa diagnostic_step, has diagnostic_id "{esc(previous)}"; '
                f'$n isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
                f'insert $x isa diagnostic_transition(prior: $p, next: $n), '
                f'has match_expression "", has transition_priority {index - 1};'
            ).resolve()
        previous = step_id


def _write_external(
    cases: list[tuple[OntologyIncident, list[str], frozenset[str]]]
) -> tuple[int, int]:
    """One WRITE txn per case (mirrors ingest._write); commits per case so a bad
    row can't drop the batch."""
    from typedb.driver import TransactionType

    from app.ontology.typedb_client import open_driver

    settings = load_settings()
    written = failed = 0
    with open_driver(settings) as driver:
        for inc, keywords, identity_tokens in cases:
            try:
                with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
                    _write_case(tx, inc, keywords, identity_tokens)
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

    written, failed = _write_external(
        [(inc, kw, _component_identity_tokens(payload)) for inc, payload, kw in prepared]
    )
    # keep set = every case the repo SHIPS (write success or not): a transient
    # write failure must never let the sweep delete a real case's knowledge.
    keep_ids = {inc.incident_id for inc, _payload, _kw in prepared}
    swept, sweep_failed = _sweep_missing_cases(load_settings(), keep_ids)
    if swept or sweep_failed:
        print(f"swept vanished cases: {len(swept)} removed, {len(sweep_failed)} failed")
    print(f"done: {written} written, {failed} failed")
    return 1 if failed and not written else 0


if __name__ == "__main__":
    raise SystemExit(main())
