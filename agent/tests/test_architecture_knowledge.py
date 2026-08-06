"""Guardrails for the platform-architecture knowledge layer.

The topology file drives operator-facing check paths and the postgres
drill-down's schema hints, so its integrity (resolvable dependencies, real
checks, component links from failure modes) is enforced offline here — the
same spirit as the failure-modes breadth guardrails.
"""

from __future__ import annotations

from app.knowledge import (
    component_check_lines,
    component_for_text,
    dependency_path,
    load_architecture,
    load_failure_modes,
)

ARCHITECTURE = "knowledge/runai_architecture.yaml"
FAILURE_MODES = "knowledge/failure_modes.yaml"


def test_architecture_loads_and_is_internally_consistent() -> None:
    components = load_architecture(ARCHITECTURE)
    assert len(components) >= 25, "expected the curated platform topology"
    for name, entry in components.items():
        assert entry["layer"] in ("cluster", "control_plane", "external"), name
        # every dependency must resolve to another curated component
        for dep in entry["depends_on"]:
            assert dep in components, f"{name}: unresolved dependency {dep!r}"
        # non-external components must carry at least one ready-to-run check
        if entry["layer"] != "external":
            assert entry["checks"], f"{name}: no checks"
            assert all("kubectl" in c for c in entry["checks"]), name


def test_component_aliases_are_unique_and_do_not_collide_with_canonical_names() -> None:
    components = load_architecture(ARCHITECTURE)

    def normalize(value: object) -> str:
        return " ".join(
            str(value).casefold().replace("_", " ").replace("-", " ").split()
        )

    canonical = {normalize(name): name for name in components}
    aliases: dict[str, str] = {}
    for name, entry in components.items():
        for alias in entry["aliases"]:
            normalized = normalize(alias)
            assert aliases.setdefault(normalized, name) == name
            assert canonical.get(normalized, name) == name


def test_component_for_text_matches_curated_aliases_without_fuzzy_matching() -> None:
    components = load_architecture(ARCHITECTURE)
    entry = component_for_text(
        components, "Thanos Receive 가 OOMKilled 반복되어서 메모리를 올렸는데도 자꾸 죽는데"
    )
    assert entry is not None and entry["component"] == "runai-backend-thanos-receive"
    assert component_for_text(components, "unrelated text") is None
    entry = component_for_text(components, "thanos-receive keeps dying")
    assert entry is not None and entry["component"] == "runai-backend-thanos-receive"


def test_live_roster_additions_and_confirmed_service_names_are_present() -> None:
    components = load_architecture(ARCHITECTURE)
    for name in (
        "application-controller",
        "init-ca",
        "runai-backend-notifications-proxy",
        "runai-backend-org-unit-helper",
        "runai-backend-redoc",
    ):
        assert name in components
    assert components["keycloak"]["services"] == ["keycloak-headless", "keycloak-http"]
    assert components["runai-backend-nats"]["services"] == [
        "runai-backend-nats", "runai-backend-nats-headless"
    ]


def test_key_sync_and_scheduling_paths_are_modeled() -> None:
    components = load_architecture(ARCHITECTURE)
    # The two sync directions the diagrams distinguish:
    assert "runai-backend-cluster-service" in dependency_path(components, "cluster-sync")
    assert "runai-backend-traefik" in dependency_path(components, "runai-agent")
    # Metrics pipeline reaches the control-plane store:
    assert "runai-backend-thanos-receive" in dependency_path(components, "prometheus-runai")
    # Scheduler path pulls its feeder controllers:
    sched = dependency_path(components, "runai-scheduler-default")
    assert "queue-controller" in sched and "pod-group-controller" in sched


def test_schema_ownership_covers_the_core_services() -> None:
    components = load_architecture(ARCHITECTURE)
    schemas = {e["owns_schema"] for e in components.values() if e["owns_schema"]}
    for expected in ("workloads", "authorization", "clusters", "audit", "org_unit"):
        assert expected in schemas, f"missing schema ownership: {expected}"


def test_component_tags_in_failure_modes_resolve() -> None:
    components = load_architecture(ARCHITECTURE)
    failure_modes = load_failure_modes(FAILURE_MODES)
    tagged = [
        (family, sym)
        for family, syms in failure_modes.items()
        for sym in syms
        if sym.get("component")
    ]
    assert len(tagged) >= 10, "component tags went missing"
    for family, sym in tagged:
        assert sym["component"] in components, (
            f"{family}/{sym['symptom']}: unknown component {sym['component']!r}"
        )


def test_check_lines_render_path_and_commands() -> None:
    components = load_architecture(ARCHITECTURE)
    lines = component_check_lines(components, "cluster-sync")
    joined = "\n".join(lines)
    assert "Check order:" in joined and "cluster-sync" in joined
    assert "kubectl logs -n runai deploy/cluster-sync" in joined
    assert component_check_lines(components, "nope") == []


def test_playbook_appends_component_check_path() -> None:
    from app.services.pipeline import ReportKnowledge, _playbook_lines

    components = load_architecture(ARCHITECTURE)
    failure_modes = load_failure_modes(FAILURE_MODES)
    lines = _playbook_lines(
                None,
                "workload status out of sync with the ui",
                "",
                knowledge=ReportKnowledge(failure_modes=failure_modes, cases="", known_issues=[], components=components),
            )
    joined = "\n".join(lines)
    assert "Cluster-Sync Out Of Sync" in joined
    assert "Check order:" in joined
    assert "kubectl logs -n runai deploy/cluster-sync" in joined


def test_container_toolkit_check_path_reaches_the_gpu_operator_stack() -> None:
    """Owner rule: runai-container-toolkit down -> look at the GPU Operator side."""
    components = load_architecture(ARCHITECTURE)
    chain = dependency_path(components, "runai-container-toolkit")
    assert "nvidia-container-toolkit-daemonset" in chain
    assert "nvidia-driver-daemonset" in chain


def test_nvidia_operator_symptoms_resolve_and_match() -> None:
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes(FAILURE_MODES)
    hits = match_failure_mode_symptoms(
        modes, 'failed to create pod sandbox: no runtime for "nvidia" is configured'
    )
    assert any(s.get("component") == "nvidia-container-toolkit-daemonset" for _, s in hits)
    hits = match_failure_mode_symptoms(
        modes, "nicclusterpolicy is not ready; gpudirect rdma missing"
    )
    assert any(s.get("component") == "network-operator" for _, s in hits)


def test_check_order_does_not_invent_dependency_edges() -> None:
    """A flattened BFS is not a chain.

    `binder` depends on runai-scheduler-default AND runai-container-toolkit;
    rendering the level order with arrows says the scheduler needs the toolkit.
    The arrow survives only where every hop really is a direct depends_on.
    """
    from app.knowledge import dependency_path, dependency_path_text

    components = {
        "top": {"depends_on": ["left", "right"]},
        "left": {"depends_on": []},
        "right": {"depends_on": []},
        "a": {"depends_on": ["b"]},
        "b": {"depends_on": ["c"]},
        "c": {"depends_on": []},
    }

    siblings = dependency_path(components, "top")
    assert siblings == ["top", "left", "right"]
    assert dependency_path_text(components, siblings) == "top, left, right"

    spine = dependency_path(components, "a")
    assert spine == ["a", "b", "c"]
    assert dependency_path_text(components, spine) == "a → b → c"


def test_real_architecture_check_orders_never_claim_a_false_spine() -> None:
    """Every rendered check order must be honest against the shipped graph."""
    from app.knowledge import dependency_path, dependency_path_text

    components = load_architecture(ARCHITECTURE)
    for name in components:
        path = dependency_path(components, name)
        if len(path) < 2:
            continue
        text = dependency_path_text(components, path)
        if " → " not in text:
            continue
        for index in range(len(path) - 1):
            deps = (components.get(path[index]) or {}).get("depends_on") or []
            assert path[index + 1] in deps, (
                f"{name}: arrow claims {path[index]} depends on {path[index + 1]}"
            )
