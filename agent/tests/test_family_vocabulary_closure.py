"""Family-vocabulary closure (2026-07-31 fix).

The family vocabulary had THREE different sizes and everything authored in the
gaps was ingested then silently discarded:
  - agent/ontology/schema.tql declares 21 root_cause subtypes
  - agent/knowledge/families.yaml (the ranker's closed vocabulary) had 16
  - agent/ontology/load_alerts.py froze a stale whitelist of 5

Concretely: 9 of 12 agent/knowledge/runai_known_issues.yaml entries declared
`platform_version_bug`/`expected_known_behavior`, which existed in schema.tql
but not in families.yaml — so `root_cause_family` was a string outside the
ranker's, the facet table's, and the evaluation flow's closed vocabulary.
Separately, load_alerts.py's 5-family whitelist silently dropped 2 of 13
built-in alerts ("NVIDIA Run:ai Container Memory Usage Critical/Warning",
family workload_runtime_error) before they ever became symptoms.

These tests pin the invariant that broke, so it stays fixed.
"""

from __future__ import annotations

import glob
from pathlib import Path

import yaml

from app.knowledge import load_family_catalog
from app.services.root_cause_ranking import _FAMILY_FACETS
from app.services.root_cause_ranking import INSUFFICIENT as _INSUFFICIENT_EVIDENCE
from ontology.load_alerts import FAMILIES as LOAD_ALERTS_FAMILIES

_KNOWLEDGE_DIR = Path(__file__).parents[1] / "knowledge"
_FAMILIES_FILE = _KNOWLEDGE_DIR / "families.yaml"


def _iter_family_values(node: object) -> list[str]:
    """Recursively collect every string value keyed "family" anywhere in a
    parsed YAML document.

    agent/knowledge/*.yaml uses several shapes for the same key: a top-level
    ``- family: x`` (runai_known_issues.yaml, runai_alerts_catalog.yaml,
    failure_modes.yaml), a ``family:`` nested inside a component entry
    (runai_architecture.yaml), and an inline ``{family: x, ...}`` deep inside a
    routing tree (k8s_troubleshooting_tree.yaml). A recursive walk is the only
    way to not miss one of them.
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "family" and isinstance(value, str) and value.strip():
                found.append(value.strip())
            else:
                found.extend(_iter_family_values(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_iter_family_values(item))
    return found


def _all_declared_families() -> set[str]:
    declared: set[str] = set()
    for path in sorted(glob.glob(str(_KNOWLEDGE_DIR / "*.yaml"))):
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        declared.update(_iter_family_values(raw))
    return declared


def test_every_declared_family_is_in_families_yaml() -> None:
    """defect (a): runai_known_issues.yaml declared platform_version_bug /
    expected_known_behavior before families.yaml had them. Must hold for
    every *.yaml directly under agent/knowledge/, not just that one file."""
    catalog = load_family_catalog(str(_FAMILIES_FILE))
    # Guards against the loader's own silent-fallback landmine: any entry
    # missing canonical_agent/agents/keywords/reason makes the WHOLE catalog
    # parse fail and silently revert to the hardcoded 16-family default,
    # which would make this test pass for the wrong reason.
    assert len(catalog.families) >= 18, (
        f"only {len(catalog.families)} families loaded — families.yaml may have "
        "failed to parse and silently fallen back to the built-in default catalog"
    )
    declared = _all_declared_families()
    # k8s_troubleshooting_tree.yaml has two leaf nodes that conclude
    # "insufficient_evidence" — root_cause_ranking.INSUFFICIENT, the ranker's
    # own "no cause cleared the bar" sentinel. It is deliberately NOT a
    # families.yaml entry (it is an output, not an input rule), yet
    # load_known_issues.py's and load_alerts.py's own FAMILIES whitelists both
    # already special-case it into their "complete set" for the same reason.
    # This is the one legitimate exception, not a drift bug.
    allowed = set(catalog.families) | {_INSUFFICIENT_EVIDENCE}
    missing = declared - allowed
    assert not missing, (
        "families declared in knowledge/*.yaml but absent from families.yaml: "
        f"{sorted(missing)}"
    )


def test_every_family_has_a_facet_entry() -> None:
    catalog = load_family_catalog(str(_FAMILIES_FILE))
    missing = [fam for fam in catalog.families if fam not in _FAMILY_FACETS]
    assert not missing, f"families.yaml families missing a _FAMILY_FACETS entry: {missing}"


def test_load_alerts_no_longer_drops_container_memory_alerts() -> None:
    """defect (b): load_alerts.py's stale 5-family whitelist dropped these 2
    of 13 built-in alerts (workload_runtime_error not in the old set) before
    they became symptoms. Assert against the filter itself, not a live
    TypeDB (load_alerts.py is a write-only TypeDB loader with no unit
    coverage otherwise; see its own module docstring)."""
    raw = yaml.safe_load(
        (_KNOWLEDGE_DIR / "runai_alerts_catalog.yaml").read_text(encoding="utf-8")
    )
    by_name = {str(e["alert"]): str(e["family"]) for e in raw}

    for name in (
        "NVIDIA Run:ai Container Memory Usage Critical",
        "NVIDIA Run:ai Container Memory Usage Warning",
    ):
        assert by_name[name] == "workload_runtime_error"
        assert by_name[name] in LOAD_ALERTS_FAMILIES

    # General regression guard: no built-in alert should be silently dropped.
    dropped = [name for name, fam in by_name.items() if fam not in LOAD_ALERTS_FAMILIES]
    assert not dropped, f"load_alerts.py would still drop: {dropped}"


def _is_bare_identity_token(keyword: str) -> bool:
    """A single unbroken token (no whitespace) has the shape of a pod name, a
    component name ("runai-backend"), a version string, a filename, or a
    config/env-var name — the exact class of false-positive keyword this repo
    has been burned by (confirmed again the day of this fix: a runbook URL
    containing "prometheus-operator" promoted a false root cause). A genuine
    error/observation string is prose with at least one space, e.g. "fallen
    off the bus" or "administrator prohibited modifying"."""
    return " " not in keyword.strip()


def test_new_family_keywords_are_not_bare_identity_tokens() -> None:
    catalog = load_family_catalog(str(_FAMILIES_FILE))
    for family in ("platform_version_bug", "expected_known_behavior"):
        _canonical, _agents, keywords = catalog.rules[family]
        assert keywords, (
            f"{family} must keep >=1 keyword or the whole catalog silently "
            "falls back to the built-in default (see loader landmine above)"
        )
        bare = [kw for kw in keywords if _is_bare_identity_token(kw)]
        assert not bare, f"{family} has bare identity-token keyword(s): {bare}"


def test_ingest_whitelists_track_families_yaml() -> None:
    """defect (b), generalized: load_alerts.py froze a stale whitelist and
    dropped alerts declaring families it had never heard of. Both loaders now
    derive their whitelist from families.yaml, so adding a family there cannot
    silently make it un-ingestable — and the two loaders cannot disagree."""
    from ontology.load_known_issues import FAMILIES as LOAD_KNOWN_ISSUES_FAMILIES

    catalog = load_family_catalog(str(_FAMILIES_FILE))
    for name, whitelist in (
        ("load_alerts", LOAD_ALERTS_FAMILIES),
        ("load_known_issues", LOAD_KNOWN_ISSUES_FAMILIES),
    ):
        missing = set(catalog.families) - set(whitelist)
        assert not missing, f"{name} would drop families.yaml families: {sorted(missing)}"
        assert _INSUFFICIENT_EVIDENCE in whitelist, f"{name} must keep the ranker sentinel"
    assert set(LOAD_ALERTS_FAMILIES) == set(LOAD_KNOWN_ISSUES_FAMILIES)


def test_symptom_names_do_not_collide_across_catalogs() -> None:
    """Symptom identity in TypeDB is the bare name string, and the loaders now
    share one reconciling `indicates` write — which deletes a symptom's edges to
    any family other than the one being written. That is correct while each
    catalog owns its own names, and silently destructive the moment two
    catalogs use the same one: the last loader to run would retire the other's
    edge."""
    catalogs = {
        "runai_alerts_catalog.yaml": ("alert", lambda d: d),
        "runai_known_issues.yaml": ("issue", lambda d: d),
        "failure_modes.yaml": (
            "name",
            lambda d: [s for fam in d for s in (fam.get("symptoms") or [])],
        ),
    }
    names: dict[str, set[str]] = {}
    for filename, (key, entries_of) in catalogs.items():
        data = yaml.safe_load((_KNOWLEDGE_DIR / filename).read_text())
        names[filename] = {
            str(entry[key]) for entry in entries_of(data) if isinstance(entry, dict) and entry.get(key)
        }
        assert names[filename], f"{filename} produced no symptom names"

    files = sorted(names)
    for i, left in enumerate(files):
        for right in files[i + 1 :]:
            shared = names[left] & names[right]
            assert not shared, (
                f"{left} and {right} both declare {sorted(shared)}; whichever loader "
                "runs last would retire the other's indicates edge"
            )
