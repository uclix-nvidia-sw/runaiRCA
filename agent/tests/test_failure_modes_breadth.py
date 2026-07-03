from __future__ import annotations

from app.knowledge import load_failure_modes
from ontology.load_knowledge import FAMILIES

YAML = "knowledge/failure_modes.yaml"


def test_yaml_parses_and_is_nonempty() -> None:
    modes = load_failure_modes(YAML)
    assert modes
    for family, symptoms in modes.items():
        assert family in FAMILIES, f"{family} missing from load_knowledge.FAMILIES"
        for symptom in symptoms:
            assert symptom["symptom"], f"unnamed symptom in {family}"
            assert symptom["keywords"], f"{symptom['symptom']} has no keywords"
            assert symptom["actions"], f"{symptom['symptom']} has no actions"


def test_keywords_are_lowercase() -> None:
    for symptoms in load_failure_modes(YAML).values():
        for symptom in symptoms:
            for kw in symptom["keywords"]:
                assert kw == kw.lower(), f"keyword not lowercase: {kw!r}"


def test_spot_checks() -> None:
    modes = load_failure_modes(YAML)
    # DNSConfigForming (seen on this cluster) is node-level knowledge with actions.
    node = {s["symptom"]: s for s in modes["node_kubelet_pressure"]}
    dns = next(s for s in node.values() if "dnsconfigforming" in s["keywords"])
    assert len(dns["actions"]) >= 2
    # GPU family exists and covers NVML mismatch + fallen off the bus.
    gpu_kws = {kw for s in modes["gpu_hardware_error"] for kw in s["keywords"]}
    assert "driver/library version mismatch" in gpu_kws
    assert "fallen off the bus" in gpu_kws
    # Registry rate limit is a distinct, more specific symptom than ImagePullBackOff.
    wl_kws = {kw for s in modes["workload_startup_image_failure"] for kw in s["keywords"]}
    assert "toomanyrequests" in wl_kws
    # Original symptoms are intact.
    assert "imagepullbackoff" in wl_kws
    assert any(s["symptom"] == "Unschedulable GPU" for s in modes["scheduling_quota_exhaustion"])


def test_specific_symptom_ordered_before_generic() -> None:
    """First keyword match wins in _kb_remediation_lines, so 'preempted by higher
    priority' must appear before the generic 'preempt' symptom."""
    symptoms = load_failure_modes(YAML)["scheduling_quota_exhaustion"]
    idx = {kw: i for i, s in enumerate(symptoms) for kw in s["keywords"]}
    assert idx["preempted by higher priority"] < idx["preempt"]


def test_every_family_exists_in_schema() -> None:
    # Family sync guardrail: a family used anywhere (YAML/loaders) but missing from
    # schema.tql fails the schema Job on deploy — catch it offline.
    import re
    from pathlib import Path

    schema = Path("ontology/schema.tql").read_text(encoding="utf-8")
    schema_families = set(re.findall(r"entity (\w+) sub root_cause", schema))
    assert FAMILIES <= schema_families, FAMILIES - schema_families


def test_layer_families_have_signatures() -> None:
    # The widened entry points must actually carry keywords (signatures), or the
    # new families are dead weight.
    modes = load_failure_modes(YAML)
    for family in (
        "network_fabric_error",
        "cluster_network_error",
        "storage_io_error",
        "workload_runtime_error",
    ):
        symptoms = modes.get(family) or []
        assert len(symptoms) >= 2, f"{family} needs at least 2 symptoms"
        assert all(s["keywords"] and s["actions"] for s in symptoms)
