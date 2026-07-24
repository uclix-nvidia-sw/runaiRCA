from __future__ import annotations

from app.knowledge import load_failure_modes, match_failure_mode_symptoms
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
    # Image pull / registry is its own family, split from the container's startup faults.
    img_kws = {kw for s in modes["image_pull_error"] for kw in s["keywords"]}
    assert "toomanyrequests" in img_kws
    assert "imagepullbackoff" in img_kws
    # kube-scheduler predicate failures live in k8s_scheduling_error.
    assert any(s["symptom"] == "Unschedulable GPU" for s in modes["k8s_scheduling_error"])


def test_image_pull_signatures_separate_auth_repository_ambiguity_and_tag() -> None:
    modes = load_failure_modes(YAML)

    def first_image_symptom(text: str) -> str:
        matches = [
            symptom["symptom"]
            for family, symptom in match_failure_mode_symptoms(
                modes, text, "image_pull_error"
            )
            if family == "image_pull_error"
        ]
        assert matches, text
        return matches[0]

    assert first_image_symptom(
        "Failed to pull image: unauthorized: authentication required"
    ) == "Registry Authentication Explicitly Rejected"
    assert first_image_symptom(
        "Failed to pull image: name unknown, repository not found"
    ) == "Image Repository Or Name Not Found"
    assert first_image_symptom(
        "ImagePullBackOff: pull access denied, repository does not exist or may require authorization"
    ) == "Repository Existence Or Authorization Ambiguous"
    assert first_image_symptom(
        "ErrImagePull: manifest for repo/app:v2 not found: manifest unknown"
    ) == "Bad Image Tag — Manifest For Tag Not Found"

    unrelated = match_failure_mode_symptoms(
        modes, "Run:ai backend request was unauthorized", "runai_control_plane_error"
    )
    assert not any(family == "image_pull_error" for family, _symptom in unrelated)


def test_node_cordon_summary_matches_k8s_scheduling_symptom() -> None:
    modes = load_failure_modes(YAML)
    summary = (
        "node/node1 is cordoned (SchedulingDisabled — spec.unschedulable=true), "
        "so it is excluded from scheduling and pending pods may report "
        "'node(s) were unschedulable'. (live firing snapshot)"
    )

    hits = match_failure_mode_symptoms(modes, summary, "")
    assert any(
        family == "k8s_scheduling_error"
        and symptom["symptom"] == "Node Cordon Excludes It From Scheduling"
        for family, symptom in hits
    )


def test_runai_mcp_oidc_discovery_is_curated_failure_mode_knowledge() -> None:
    modes = load_failure_modes(YAML)
    symptom = next(
        item
        for item in modes["workload_startup_error"]
        if item["symptom"] == "Run:ai MCP OIDC Discovery Returns HTML Instead of JSON"
    )

    assert "OIDC JSON document" in symptom["reason"]
    assert "OIDC JSON 문서" in symptom["reason_ko"]
    assert symptom["exclusive_actions"] is True
    assert any("/api/v1/token" in action for action in symptom["actions"])
    assert any("runaiMcp.oidcIssuerUrl" in action for action in symptom["actions_ko"])


def test_oomkilled_has_exclusive_pod_level_remediation() -> None:
    modes = load_failure_modes(YAML)
    symptom = next(
        item
        for item in modes["workload_runtime_error"]
        if item["symptom"] == "OOMKilled"
    )

    assert symptom["exclusive_actions"] is True
    assert "memory limit" in symptom["reason"]
    assert "메모리 제한" in symptom["reason_ko"]
    assert any("resources.limits.memory" in action for action in symptom["actions"])
    assert any("Node-level OOM" in action for action in symptom["actions_ko"])


def test_specific_symptom_ordered_before_generic() -> None:
    """First keyword match wins in _kb_remediation_lines, so 'preempted by higher
    priority' must appear before the generic 'preempt' symptom."""
    symptoms = load_failure_modes(YAML)["runai_scheduling_quota"]
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
        "k8s_storage_error",
        "workload_runtime_error",
    ):
        symptoms = modes.get(family) or []
        assert len(symptoms) >= 2, f"{family} needs at least 2 symptoms"
        assert all(s["keywords"] and s["actions"] for s in symptoms)


def test_fabric_manager_failure_mode_distinctions_match() -> None:
    modes = load_failure_modes(YAML)

    def symptoms_for(text: str) -> set[str]:
        return {
            symptom["symptom"]
            for family, symptom in match_failure_mode_symptoms(modes, text, "")
            if family == "network_fabric_error"
        }

    assert "NVSwitch SXid Access And Trunk Link Failure" in symptoms_for(
        "NVSwitch SXid fatal on a trunk link"
    )
    assert "GPU Fabric Registration Incomplete" in symptoms_for(
        "GPU fabric State: In Progress / cudaErrorSystemNotReady"
    )
    assert "MIG Mode Disables NVLink" in symptoms_for("MIG mode disables NVLink peer-to-peer")


def test_fabric_manager_sxid_and_partition_lifecycle_match_specific_symptoms() -> None:
    modes = load_failure_modes(YAML)

    def symptoms_for(text: str) -> set[str]:
        return {
            symptom["symptom"]
            for family, symptom in match_failure_mode_symptoms(modes, text, "")
            if family == "network_fabric_error"
        }

    assert "NVSwitch SXid — Always Fatal" in symptoms_for("NVSwitch SXid 23001 fatal")
    assert "NVSwitch SXid Access And Trunk Link Failure" in symptoms_for(
        "SXid 20034 LTSSM Fault, GPU Xid 74"
    )
    assert "Fabric Partition Life-Cycle Errors" in symptoms_for(
        "FM_ST_IN_USE partition already activated"
    )
    assert "NVSwitch SXid — Other Notable" in symptoms_for(
        "Host_thermal_event_start single lane"
    )


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

    assert "runai_scheduling_quota" in fam_for("node defragmentation blocks the 4-gpu pod")
    assert "runai_scheduling_quota" in fam_for("workload suspended due to idleness rule")
    assert "runai_control_plane_error" in fam_for(
        "cluster-sync is out of sync with the workload status"
    )
    assert "runai_control_plane_error" in fam_for("cluster disconnected: token used before issued")
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
        "runai_scheduling_quota": [
            "runai reclaimed over-quota gpus to rebalance fairshare",
            "node defragmentation, gpus free but not on a single node",
            "workload suspended due to idleness rule",
        ],
        "observability_accuracy": [
            "no metrics, thanos-receive storage full",
            "gpu number 0, dcgm_fi_dev_fb_used missing on some nodes",
            "metrics-exporter target down",
        ],
        "runai_control_plane_error": [
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
    assert {f for f, _ in kube} == {"k8s_scheduling_error"}
    assert any(s["symptom"].startswith("Which Scheduler") for _, s in kube)

    # runai-scheduler placement failure → the Run:ai scheduling family
    assert fams("runai-scheduler-default cannot place pod group") == {"runai_scheduling_quota"}

    # the disambiguation action names both schedulers + how to tell them apart
    which = next(s for _, s in kube if s["symptom"].startswith("Which Scheduler"))
    joined = " ".join(which["actions"]).lower()
    assert "schedulername" in joined
    assert "runai-scheduler-default" in joined and "default-scheduler" in joined


def test_k8s_research_signatures_map_to_right_family_single_track() -> None:
    # Signatures ingested from the learnk8s flowchart + k8s docs + CNCF research must
    # each match exactly ONE family (no cross-track bleed).
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes("knowledge/failure_modes.yaml")

    def only(text):
        return {f for f, _ in match_failure_mode_symptoms(modes, text, "")}

    assert only("createcontainerconfigerror: couldn't find key api_key in secret") == {
        "workload_startup_error"
    }
    assert only("0/5 nodes are available: 3 untolerated taint, 2 didn't match node selector") == {
        "k8s_scheduling_error"
    }
    assert only("service myapp has no endpoints available") == {"cluster_network_error"}
    assert only("pleg is not healthy: pleg was last active 5m ago") == {"node_kubelet_pressure"}
    # k8s cluster control plane (distinct from the Run:ai platform control plane)
    assert only("etcdserver: request timed out, no leader") == {"k8s_control_plane_error"}
    assert only("volume node affinity conflict") == {"k8s_storage_error"}
    assert only("error from server (forbidden): cannot list resource pods") == {
        "platform_auth_error"
    }
    # cert text stays with the registry (workload) track; k8s control-plane cert uses
    # kubeadm-specific phrasing so the two don't collide
    assert "k8s_control_plane_error" not in only("certificate has expired")
    assert only("kubeadm certs check-expiration shows apiserver expired") == {
        "k8s_control_plane_error"
    }
    # the Run:ai platform control plane is a SEPARATE family from the k8s one
    assert only("runai cluster-sync is out of sync") == {"runai_control_plane_error"}


def test_subsystem_splits_stay_separate() -> None:
    # The coarse families were split by subsystem (k8s vs Run:ai scheduler, image
    # vs startup, k8s-storage vs backend-storage). Each representative signature must
    # match exactly ONE family — no bleed back across the split.
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes("knowledge/failure_modes.yaml")
    expect = {
        "k8s_scheduling_error": [
            "default-scheduler failedscheduling 0/5 nodes untolerated taint",
            "exceeded quota: pods forbidden",
        ],
        "runai_scheduling_quota": [
            "runai reclaimed over-quota gpus fairshare",
            "gang pod group not scheduling",
            "preempted by higher priority",
        ],
        "image_pull_error": [
            "imagepullbackoff errimagepull",
            "toomanyrequests pull rate limit",
            "manifest for tag not found",
        ],
        "workload_startup_error": [
            "crashloopbackoff back-off restarting failed container",
            "createcontainerconfigerror couldn't find key",
        ],
        "k8s_storage_error": [
            "unbound immediate persistentvolumeclaims storageclass",
            "volume node affinity conflict",
        ],
        "storage_backend_error": [
            "nfs: server not responding stale file handle",
            "ceph slow ops osd down",
            "read-only file system",
        ],
    }
    for family, texts in expect.items():
        for text in texts:
            fams = {f for f, _ in match_failure_mode_symptoms(modes, text, "")}
            assert fams == {family}, f"{text!r} -> {fams}, expected {{{family}}}"


def test_concrete_image_pull_error_leads_generic_retry_state() -> None:
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    matches = match_failure_mode_symptoms(
        load_failure_modes("knowledge/failure_modes.yaml"),
        "ErrImagePull: dial tcp: lookup registry.airgap.local: no such host while pulling image",
    )

    assert matches[0][0] == "image_pull_error"
    assert matches[0][1]["symptom"] == "Registry Server 5xx / DNS Lookup Failure On Pull"
    assert matches[-1][1]["symptom"] == "ImagePullBackOff"


def test_historical_dashboard_side_signal_does_not_beat_live_manifest_error() -> None:
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    matches = match_failure_mode_symptoms(
        load_failure_modes("knowledge/failure_modes.yaml"),
        "ErrImagePull: manifest unknown for trainer image; no container started, "
        "later dashboard mentioned cuda out of memory from old run",
    )

    assert matches[0][0] == "image_pull_error"
    assert matches[0][1]["symptom"] == "Bad Image Tag — Manifest For Tag Not Found"
    assert all(family != "workload_runtime_error" for family, _symptom in matches)
