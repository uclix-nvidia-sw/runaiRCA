"""Asynchronously reconcile incident-derived knowledge packages into TypeDB.

This is an advisory mirror. Agent activation remains controlled by the backend
package lifecycle; a failed mirror only reports failure and never blocks it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from app.config import load_settings
from app.ontology.typedb_client import escape_typeql as esc
from app.ontology.typedb_client import open_driver
from ontology.ingest import _ensure, _iso_or_empty, _replace_attr
from ontology.load_knowledge import (
    _concept_value,
    _ensure_cause,
    _ensure_symptom,
)
from ontology.upsert import (
    ensure_action,
    relate_symptom_indicates,
    relate_symptom_resolved_by,
)

_SELECT_PACKAGES = """
SELECT p.package_id, p.case_id, p.status, p.payload, p.published_at::text AS published_at,
       COALESCE(p.retired_at::text, '') AS retired_at, c.trace
  FROM knowledge_packages p
  JOIN knowledge_candidates c ON c.candidate_id = p.candidate_id
 ORDER BY p.published_at ASC, p.package_id ASC
 LIMIT $1
"""

_MIRROR_ERROR_MAX = 240


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


async def _fetch(limit: int) -> list[dict[str, Any]]:
    import asyncpg

    settings = load_settings()
    if not settings.postgres_dsn:
        print("POSTGRES_DSN not set; skipping package mirror.")
        return []
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        rows = await conn.fetch(_SELECT_PACKAGES, max(1, limit))
    finally:
        await conn.close()
    return [dict(row) for row in rows]


def _safe_error(exc: BaseException) -> str:
    """A bounded status message that never persists driver/server payloads."""
    # Driver exception text can include endpoint details, query fragments, or
    # credentials. Persist its class only; detailed diagnostics remain in the
    # CronJob log under cluster access controls.
    return f"TypeDB mirror failed ({type(exc).__name__})"[:_MIRROR_ERROR_MAX]


async def _set_mirror_state(package_id: str, status: str, error: str = "") -> None:
    """Update advisory mirror state without touching package activation state."""
    import asyncpg

    settings = load_settings()
    if not settings.postgres_dsn:
        raise RuntimeError("POSTGRES_DSN is required to record package mirror state")
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        await conn.execute(
            """
            UPDATE knowledge_packages
               SET mirror_status = $1,
                   mirror_last_error = $2,
                   mirror_updated_at = now()
             WHERE package_id = $3
            """,
            status,
            error[:_MIRROR_ERROR_MAX],
            package_id,
        )
    finally:
        await conn.close()


def _record_mirror_state(package_id: str, status: str, error: str = "") -> bool:
    try:
        asyncio.run(_set_mirror_state(package_id, status, error))
    except Exception as exc:  # noqa: BLE001 - do not make the mirror state write a package gate
        print(
            f"  ! package {package_id}: could not record mirror state ({type(exc).__name__})",
            file=sys.stderr,
        )
        return False
    return True


def _compiled_template_ids(payload: dict[str, Any]) -> list[str]:
    """Return only the package compiler's identifier-only approved templates."""
    compiled = payload.get("compiled")
    if not isinstance(compiled, dict):
        return []
    raw = compiled.get("probe_template_ids")
    if not isinstance(raw, dict):
        return []
    ids: list[str] = []
    # The compiler owns the family -> [template ID] selection. Any malformed
    # family value invalidates the binding set rather than widening scope.
    if not all(
        isinstance(values, list)
        and all(isinstance(item, str) and item.strip() for item in values)
        for values in raw.values()
    ):
        return []
    for family in sorted(raw):
        values = raw[family]
        family_ids = [item.strip() for item in values]
        for template_id in sorted(family_ids):
            if template_id not in ids:
                ids.append(template_id)
    return ids


def _binding_id(package_id: str, template_id: str) -> str:
    """Version the binding by its package-local ``step_id:pNN`` identifier."""
    parts = template_id.split(":", 1)
    probe_local_id = parts[1] if len(parts) == 2 else template_id
    return f"{package_id}:v1:{probe_local_id}"


def _compiled_symptoms(payload: dict[str, Any]) -> list[tuple[str, str, list[str], list[str]]]:
    """(family, symptom, keywords, actions) for the catalog knowledge to mirror.

    ``novel_*`` families are deliberately excluded. They are matcher-only by
    construction and the pipeline drops non-catalog families out of graph
    knowledge anyway, so writing them here would add a root_cause subtype the
    graph can never use.
    """
    compiled = payload.get("compiled")
    if not isinstance(compiled, dict):
        return []
    out: list[tuple[str, str, list[str], list[str]]] = []
    for mode in compiled.get("failure_modes") or []:
        if not isinstance(mode, dict):
            continue
        family = str(mode.get("family") or "").strip()
        if not family or family.startswith("novel_"):
            continue
        for symptom in mode.get("symptoms") or []:
            if not isinstance(symptom, dict):
                continue
            name = str(symptom.get("name") or symptom.get("symptom") or "").strip()
            keywords = [
                str(keyword).strip().lower()
                for keyword in symptom.get("keywords") or []
                if str(keyword).strip()
            ]
            if not name or not keywords:
                continue
            actions = [
                str(action).strip()
                for action in symptom.get("actions") or []
                if str(action).strip()
            ]
            out.append((family, name, keywords, actions))
    return out


def _symptom_owner(tx: Any, name: str) -> tuple[bool, str]:
    """(exists, learned_package_id) for one symptom name."""
    rows = list(
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; select $s;'
        ).resolve().as_concept_rows()
    )
    if not rows:
        return False, ""
    owners = list(
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}", '
            "has learned_package_id $p; select $p;"
        ).resolve().as_concept_rows()
    )
    for row in owners:
        get = getattr(row, "get", None)
        if callable(get) and (concept := get("p")) is not None:
            return True, str(_concept_value(concept)).strip()
    return True, ""


def _retract_learned_symptom(tx: Any, name: str) -> None:
    for relation, role in (("indicates", "symptom"), ("resolved_by", "symptom")):
        tx.query(
            f"match $rel isa {relation}, links ({role}: $s); "
            f'$s isa symptom, has name "{esc(name)}"; delete $rel;'
        ).resolve()
    tx.query(f'match $s isa symptom, has name "{esc(name)}"; delete $s;').resolve()


def _mirror_learned_knowledge(tx: Any, row: dict[str, Any]) -> tuple[int, int]:
    """Project one package's approved knowledge into the graph, or retract it.

    Written as ordinary ``symptom``/``indicates``/``resolved_by`` — the same
    shapes curated knowledge uses — so every existing consumer picks it up with
    no second query. ``learned_package_id`` marks the rows as ours: a retired
    package removes exactly those and nothing else, and a curated symptom that
    happens to share a name is left alone (the curated one wins).
    """
    package_id = str(row.get("package_id") or "").strip()
    payload = _object(row.get("payload"))
    active = str(row.get("status") or "").strip() == "active"
    written = skipped = 0
    for family, name, keywords, actions in _compiled_symptoms(payload):
        exists, owner = _symptom_owner(tx, name)
        if exists and owner != package_id:
            # Either curated (no owner) or another package's: never overwrite.
            # _relate_indicates retires competing family edges, so writing here
            # could silently move a curated symptom to this package's family.
            skipped += 1
            continue
        if not active:
            if exists:
                _retract_learned_symptom(tx, name)
                written += 1
            continue
        _ensure_cause(tx, family)
        _ensure_symptom(tx, name, keywords)
        _replace_attr(tx, "symptom", "name", name, "learned_package_id", package_id)
        relate_symptom_indicates(tx, name, family)
        for statement in actions:
            ensure_action(tx, statement)
            relate_symptom_resolved_by(tx, name, statement)
        written += 1
    return written, skipped


def _write_package(tx: Any, row: dict[str, Any]) -> tuple[int, int]:
    package_id = str(row.get("package_id") or "").strip()
    if not package_id:
        return 0, 0
    payload = _object(row.get("payload"))
    status = str(row.get("status") or "").strip()
    _ensure(tx, "knowledge_package", "package_id", package_id)
    for attr, value in {
        "package_status": status,
        "case_id": str(row.get("case_id") or ""),
        "title": str(payload.get("title") or ""),
        "summary": str(payload.get("summary") or ""),
        "hypothesis_family": str(payload.get("family") or ""),
        "package_published_at": _iso_or_empty(row.get("published_at")),
        "package_retired_at": _iso_or_empty(row.get("retired_at")),
    }.items():
        if value:
            _replace_attr(tx, "knowledge_package", "package_id", package_id, attr, value)
    bound = missing = 0
    active = status == "active"
    # Never infer a package binding from its broader reasoning trace. The
    # compiler publishes this narrow identifier-only list after approval.
    for template_id in _compiled_template_ids(payload):
        template = (
            f'$t isa diagnostic_probe_template, has probe_id "{esc(template_id)}"; '
        )
        if not list(tx.query(f"match {template} select $t;").resolve().as_concept_rows()):
            missing += 1
            continue
        # The binding identity is intentionally package/version/local-probe;
        # the full bundled ID remains only on the template relation target.
        binding_id = _binding_id(package_id, template_id)
        _ensure(tx, "package_template_binding", "package_template_binding_id", binding_id)
        _replace_attr(
            tx,
            "package_template_binding",
            "package_template_binding_id",
            binding_id,
            "template_active",
            active,
            quoted=False,
        )
        match = (
            f'$p isa knowledge_package, has package_id "{esc(package_id)}"; '
            f'$t isa diagnostic_probe_template, has probe_id "{esc(template_id)}"; '
            f'$b isa package_template_binding, has package_template_binding_id "{esc(binding_id)}"; '
        )
        relation = "$x isa package_has_template, links (package: $p, template: $t, binding: $b)"
        if not list(tx.query(f"match {match}{relation}; select $x;").resolve().as_concept_rows()):
            tx.query(f"match {match} insert {relation};").resolve()
        bound += 1
    return bound, missing


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile approved knowledge packages into TypeDB.")
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()
    try:
        rows = asyncio.run(_fetch(args.limit))
    except Exception as exc:  # noqa: BLE001 - report a non-blocking mirror failure
        print(f"package mirror fetch failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if not rows:
        print("package mirror: no packages")
        return 0
    settings = load_settings()
    mirrored = retired = bindings = missing = failed = 0
    knowledge = collisions = 0
    try:
        from typedb.driver import TransactionType

        driver = open_driver(settings)
    except Exception as exc:  # noqa: BLE001 - every fetched package remains retryable
        safe_error = _safe_error(exc)
        for row in rows:
            package_id = str(row.get("package_id") or "")
            if package_id:
                _record_mirror_state(package_id, "error", safe_error)
        print(f"package mirror unavailable: {safe_error}", file=sys.stderr)
        return 1
    with driver:
        for row in rows:
            package_id = str(row.get("package_id") or "")
            try:
                with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
                    bound, absent = _write_package(tx, row)
                    written, skipped = _mirror_learned_knowledge(tx, row)
                    tx.commit()
                knowledge += written
                collisions += skipped
                if not _record_mirror_state(package_id, "synced"):
                    failed += 1
                    continue
                mirrored += 1
                retired += int(str(row.get("status") or "") == "retired")
                bindings += bound
                missing += absent
            except Exception as exc:  # noqa: BLE001 - one bad package must not block the mirror
                failed += 1
                safe_error = _safe_error(exc)
                _record_mirror_state(package_id, "error", safe_error)
                print(f"  ! package {package_id}: {safe_error}", file=sys.stderr)
    print(
        "package mirror: "
        f"{mirrored} mirrored, {retired} retired marked inactive, {bindings} template bindings, "
        f"{missing} missing authored templates, {knowledge} learned symptoms written/retracted, "
        f"{collisions} skipped (name already curated), {failed} failed"
    )
    # A partial run still mirrors the healthy packages, but remains retryable
    # through the CronJob's backoff and next schedule for failed ones.
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
