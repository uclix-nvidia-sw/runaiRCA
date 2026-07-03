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


def test_runai_scheduler_reclaim_and_gang_surface_with_scheduler_pod_pointer() -> None:
    # Run:ai's own scheduler (separate from kube-scheduler): a reclaimed or gang-stuck
    # workload must match a symptom whose action points at runai-scheduler-default.
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes("knowledge/failure_modes.yaml")

    reclaim = match_failure_mode_symptoms(
        modes, "runai-scheduler reclaimed over-quota gpus from project vision", ""
    )
    assert any(s.get("symptom") == "Reclaimed To Rebalance Fairshare" for _, s in reclaim)
    assert any("runai-scheduler-default" in a for _, s in reclaim for a in s.get("actions", []))

    gang = match_failure_mode_symptoms(
        modes, "pod group is unschedulable: not enough resources to gang the group", ""
    )
    assert any(s.get("symptom") == "Gang Or Pod-Group Not Scheduling" for _, s in gang)


def test_nvidia_common_issues_deck_knowledge_surfaces() -> None:
    # Signatures from the official NVIDIA "Common Troubleshooting" deck must each
    # match a symptom in the RIGHT family.
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes("knowledge/failure_modes.yaml")

    def fam_for(text):
        hits = match_failure_mode_symptoms(modes, text, "")
        return {f for f, _ in hits}

    assert "scheduling_quota_exhaustion" in fam_for("node defragmentation blocks the 4-gpu pod")
    assert "scheduling_quota_exhaustion" in fam_for("workload suspended due to idleness rule")
    assert "control_plane_error" in fam_for("cluster-sync is out of sync with the workload status")
    assert "control_plane_error" in fam_for("cluster disconnected: token used before issued")
    assert "observability_accuracy" in fam_for("no metrics: thanos-receive storage full")
    assert "observability_accuracy" in fam_for("gpu number is 0, dcgm_fi_dev_fb_used missing")
    assert "platform_auth_error" in fam_for("user failed to authenticate, email_verified missing")
    assert "platform_auth_error" in fam_for("saml assertionconsumerservice mismatch")

    # Every new-family action carries a concrete pod/dashboard pointer, not just prose.
    metrics = match_failure_mode_symptoms(modes, "thanos-query cannot reach thanos-receive", "")
    assert any("runai-backend" in a for _, s in metrics for a in s.get("actions", []))


def test_deck_four_tracks_stay_separate_no_cross_matching() -> None:
    # The NVIDIA deck's 4 flows (auth, workloads, metrics, cluster-disconnected) are
    # INDEPENDENT diagnostic tracks. A single-track evidence line must match ONLY its
    # own family — no bleeding auth guidance into a metrics incident, etc.
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes("knowledge/failure_modes.yaml")
    tracks = {
        "platform_auth_error": [
            "user failed to authenticate, email_verified missing",
            "saml assertionconsumerservice mismatch, attributestatement missing email",
            "oidc discovery url wrong, client secret invalid",
        ],
        "scheduling_quota_exhaustion": [
            "workload pending, node pool insufficient cpu",
            "node defragmentation, gpus free but not on a single node",
            "workload suspended due to idleness rule",
        ],
        "observability_accuracy": [
            "no metrics, thanos-receive storage full",
            "gpu number 0, dcgm_fi_dev_fb_used missing on some nodes",
            "metrics-exporter target down",
        ],
        "control_plane_error": [
            "cluster disconnected, traefik token used before issued",
            "missing prerequisites, runai-toolkit crash",
        ],
    }
    for expected, texts in tracks.items():
        for text in texts:
            fams = {f for f, _ in match_failure_mode_symptoms(modes, text, "")}
            assert fams == {expected}, f"{text!r} bled into {fams - {expected}}"


def test_scheduler_disambiguation_runai_vs_kube() -> None:
    # A scheduler failure must be attributed to the RIGHT scheduler, and a plain
    # kube default-scheduler event must NOT elevate the Run:ai control plane.
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes("knowledge/failure_modes.yaml")

    def fams(text):
        return {f for f, _ in match_failure_mode_symptoms(modes, text, "")}

    # kube default-scheduler event → scheduling track only, NOT control_plane
    kube = match_failure_mode_symptoms(
        modes, "default-scheduler failedscheduling insufficient cpu", ""
    )
    assert {f for f, _ in kube} == {"scheduling_quota_exhaustion"}
    assert any(s["symptom"].startswith("Which Scheduler") for _, s in kube)

    # runai-scheduler placement failure → scheduling track only, NOT control_plane
    assert fams("runai-scheduler-default cannot place pod group") == {"scheduling_quota_exhaustion"}

    # the disambiguation action names both schedulers + how to tell them apart
    which = next(s for _, s in kube if s["symptom"].startswith("Which Scheduler"))
    joined = " ".join(which["actions"]).lower()
    assert "schedulername" in joined
    assert "runai-scheduler-default" in joined and "default-scheduler" in joined
