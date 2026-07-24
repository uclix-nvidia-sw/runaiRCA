from __future__ import annotations

from pathlib import Path

import yaml

from app.knowledge import (
    DEFAULT_FAMILIES,
    DEFAULT_FAMILY_HINTS,
    DEFAULT_FAMILY_REASONS,
    DEFAULT_FAMILY_RULES,
    family_catalog_from_entries,
    load_family_catalog,
    _load_failure_modes,
)

FAMILIES = Path(__file__).parents[1] / "knowledge" / "families.yaml"


def test_families_yaml_matches_builtin_catalog() -> None:
    raw = yaml.safe_load(FAMILIES.read_text(encoding="utf-8"))
    catalog = family_catalog_from_entries(raw)

    assert catalog is not None
    assert catalog.families == DEFAULT_FAMILIES
    assert catalog.rules == DEFAULT_FAMILY_RULES
    assert catalog.hints == DEFAULT_FAMILY_HINTS
    assert catalog.reasons == DEFAULT_FAMILY_REASONS
    assert load_family_catalog(str(FAMILIES)) == catalog


def test_oomkilled_is_runtime_not_startup_keyword() -> None:
    catalog = load_family_catalog(str(FAMILIES))

    assert "oomkilled" not in catalog.rules["workload_startup_error"][2]
    assert "oomkilled" in catalog.rules["workload_runtime_error"][2]
    modes = _load_failure_modes("knowledge/failure_modes.yaml")
    assert any(item["symptom"] == "OOMKilled" for item in modes["workload_runtime_error"])
    assert not any(item["symptom"] == "OOMKilled" for item in modes["workload_startup_error"])
