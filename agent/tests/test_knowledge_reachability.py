"""Offline reachability guardrails for shipped knowledge catalogs."""

from __future__ import annotations

from pathlib import Path

import yaml

from app.knowledge import (
    _keyword_hits,
    component_for_text,
    load_architecture,
    load_family_catalog,
)
from ontology.load_external_cases import (
    _chain_specific,
    _clean_keyword,
    _symptom_keywords,
    _validate,
)

ROOT = Path(__file__).parents[1]
ARCHITECTURE = ROOT / "knowledge/runai_architecture.yaml"
EXTERNAL_CASES = ROOT / "knowledge/external_cases"
FAILURE_MODES = ROOT / "knowledge/failure_modes.yaml"
FAMILIES = ROOT / "knowledge/families.yaml"
KNOWN_ISSUES = ROOT / "knowledge/runai_known_issues.yaml"
ALERTS = ROOT / "knowledge/runai_alerts_catalog.yaml"
# Label-supported known-issue-only verdict families; see family_label in app/knowledge.py.
KNOWN_ISSUE_ONLY_FAMILIES = {"platform_version_bug", "expected_known_behavior"}


def _yaml(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or []


def _case_id(payload: dict) -> str:
    return str((payload.get("identity") or {}).get("deduplication_key") or "<missing case id>")


def test_external_cases_have_a_reachable_signature() -> None:
    components = load_architecture(str(ARCHITECTURE))
    for path in sorted(EXTERNAL_CASES.glob("*/03_ingestion_payload.yaml")):
        payload = _yaml(path)
        if not isinstance(payload, dict) or _validate(payload):
            continue
        case_id = _case_id(payload)
        keywords = _symptom_keywords(payload)
        assert keywords, f"{path}: {case_id}: no symptom keywords"

        context = payload.get("searchable_context") or {}
        signature_keywords = {
            _clean_keyword(value).lower()
            for field in ("error_signatures", "curated_signature_tokens")
            for value in context.get(field) or []
        }
        specific = [
            keyword
            for keyword in keywords
            if keyword in signature_keywords and _chain_specific(keyword)
        ]
        known_components: list[str] = []
        unknown_components: list[str] = []
        for value in context.get("canonical_component_tokens") or []:
            token = _clean_keyword(value).lower()
            if token not in keywords:
                continue
            if token in components or component_for_text(components, token):
                known_components.append(token)
            else:
                unknown_components.append(token)
        assert specific or known_components, (
            f"{path}: {case_id}: unreachable keywords; unknown component tokens "
            f"{unknown_components or '<none>'}"
        )


def test_thanos_case_replays_the_component_retrieval_path() -> None:
    path = EXTERNAL_CASES / "case-e38f69ff583a/03_ingestion_payload.yaml"
    payload = _yaml(path)
    assert isinstance(payload, dict), f"{path}: invalid payload"
    components = load_architecture(str(ARCHITECTURE))
    question = "Thanos Receive 가 OOMKilled 반복되어서 메모리를 올렸는데도 자꾸 죽는데"
    entry = component_for_text(components, question)
    assert entry is not None, f"{path}: {_case_id(payload)}: component did not resolve"
    hits, _negated = _keyword_hits(f"{question}\n{entry['component']}", _symptom_keywords(payload))
    assert hits, f"{path}: {_case_id(payload)}: component join did not hit a case keyword"


def test_failure_modes_have_closed_families_and_unique_reachable_symptoms() -> None:
    catalog = load_family_catalog(str(FAMILIES)).families
    names: dict[str, str] = {}
    for entry in _yaml(FAILURE_MODES):
        assert isinstance(entry, dict), f"{FAILURE_MODES}: invalid family entry"
        family = str(entry.get("family") or "").strip()
        assert family in catalog, f"{FAILURE_MODES}: {family or '<missing family>'}: not in catalog"
        for symptom in entry.get("symptoms") or []:
            assert isinstance(symptom, dict), f"{FAILURE_MODES}: {family}: invalid symptom"
            name = str(symptom.get("name") or "").strip()
            assert name, f"{FAILURE_MODES}: {family}: unnamed symptom"
            assert symptom.get("keywords"), f"{FAILURE_MODES}: {family}/{name}: no keywords"
            assert symptom.get("actions"), f"{FAILURE_MODES}: {family}/{name}: no actions"
            assert name not in names, (
                f"{FAILURE_MODES}: {family}/{name}: also in {names[name]}"
            )
            names[name] = family


def test_known_issues_are_not_silently_dropped_by_the_loader() -> None:
    families = set(load_family_catalog(str(FAMILIES)).families) | KNOWN_ISSUE_ONLY_FAMILIES
    for index, entry in enumerate(_yaml(KNOWN_ISSUES)):
        assert isinstance(entry, dict), f"{KNOWN_ISSUES}: entry {index}: invalid issue"
        name = str(entry.get("issue") or "").strip()
        assert name, f"{KNOWN_ISSUES}: entry {index}: missing issue name"
        keywords = [str(keyword).strip() for keyword in entry.get("keywords") or []]
        assert any(keywords), f"{KNOWN_ISSUES}: {name}: no keywords"
        family = str(entry.get("family") or "").strip()
        assert not family or family in families, f"{KNOWN_ISSUES}: {name}: unknown family {family}"


def test_actionable_alerts_have_a_catalog_entry_point() -> None:
    for index, entry in enumerate(_yaml(ALERTS)):
        assert isinstance(entry, dict), f"{ALERTS}: entry {index}: invalid alert"
        if entry.get("actions"):
            name = str(entry.get("alert") or "").strip()
            assert name, f"{ALERTS}: entry {index}: actions without alert name"
