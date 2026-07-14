"""Deterministic root-cause *candidate* ranking.

Ranks EVERY family in knowledge/families.yaml (the same 15-family universe the
curated failure modes use — the ranked categories and the ontology knowledge
finally speak one vocabulary) for the CURRENT incident from the evidence the
collectors already gathered. This is NOT incident similarity — pgvector /
`similarIncidentsLocked` in the Go backend owns "which past incidents are
similar". Here we answer "which failure family does this incident's evidence
point to, and how confidently", and cite the agents that back each candidate.

Encodes rules R1-R6 from agent/knowledge/troubleshooting_cases.md. Keyword
heuristics over collector text, not a model.

ponytail: substring keyword scan over each collector's summary/artifacts/details,
scoped per family to the agents that own that signal. Upgrade to structured
detail parsing (or an LLM judge) only if the eval hit-rate stalls.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.collectors.base import AnalysisTarget, CollectorResult
from app.knowledge import _keyword_hits, load_family_catalog
from app.services.evidence_blackboard import source_independence_group

_FAMILY_CATALOG = load_family_catalog(os.getenv("FAMILIES_FILE", "knowledge/families.yaml"))
FAMILIES = _FAMILY_CATALOG.families
INSUFFICIENT = "insufficient_evidence"
_FAMILY_RULES = _FAMILY_CATALOG.rules

_FLOOR = 2.0          # min top score below which we fall back to insufficient_evidence
_HIGH = 5.0           # score needed (with >=2 corroborating agents) for high confidence
_MED = 2.5
_CONF_ORDER = ("low", "medium", "high")
# Values that describe what we ASKED or which objects EXIST, not what came back.
# Matching keywords against them let a run with ZERO error evidence score
# runai_control_plane_error 8.0/high: the LogQL probe strings carried
# "reconcile|cluster-sync|authorization" and the healthy control-plane pod
# LISTING carried "runai-backend-*" names. Evidence text = returned values only.
METADATA_VALUE_KEYS = {
    "expr",
    "expression",
    "metric",
    "metric_name",
    "name",
    "query",
    "path",
    "url",
    "title",
    "label_selector",
    "labelselector",
    "field_selector",
    "fieldselector",
    "logql",
    "promql",
    "sql",
    "kubectl",
    "runai_control_plane_pods",
    # Our OWN probe/transport failures ("no route to host" to an MCP service,
    # a 401 from a stale agent credential) are not cluster evidence. Kernel/log
    # lines live under "errors"/"lines"/"message" keys and stay matchable.
    "error",
    "mcp_fallback",
}
_METADATA_VALUE_KEYS = METADATA_VALUE_KEYS

# ---------------------------------------------------------------------------
# Multi-axis facets: (Locus, Nature) per family. The family label stays the
# headline; these annotate the incident on two intrinsic axes so operators (and
# downstream calibration) can reason across families:
#   - subsystem (Locus): WHERE the cause sits (gpu / node / network / ...).
#   - nature: WHAT KIND of cause — "fault" (a defect), "saturation" (resource
#     exhaustion/pressure), "lifecycle_change" (expected rollout/upgrade
#     disruption), or "observability" (the monitoring itself, not the workload).
# The Trigger axis (what SET IT OFF) is dynamic, not intrinsic to the family, so
# it is filled by the ranker from the lifecycle/change signal, not from here.
# ---------------------------------------------------------------------------
_FAMILY_FACETS: dict[str, tuple[str, str]] = {
    "node_kubelet_pressure": ("node", "saturation"),
    "runai_scheduling_quota": ("scheduling", "saturation"),
    "k8s_scheduling_error": ("scheduling", "fault"),
    "runai_control_plane_error": ("control-plane", "fault"),
    "k8s_control_plane_error": ("control-plane", "fault"),
    "workload_startup_error": ("workload", "fault"),
    "image_pull_error": ("registry", "fault"),
    "gpu_hardware_error": ("gpu", "fault"),
    "network_fabric_error": ("network", "fault"),
    "cluster_network_error": ("network", "fault"),
    "k8s_storage_error": ("storage", "fault"),
    "storage_backend_error": ("storage", "fault"),
    "workload_runtime_error": ("workload", "fault"),
    "observability_accuracy": ("observability", "observability"),
    "platform_auth_error": ("auth", "fault"),
    "platform_lifecycle_change": ("platform-lifecycle", "lifecycle_change"),
}


def _family_facets(family: str) -> tuple[str, str]:
    """(subsystem, nature) for a family; ('', '') for non-causes (insufficient)."""
    return _FAMILY_FACETS.get(family, ("", ""))


def _lifecycle_trigger(lifecycle: dict[str, Any] | None) -> str:
    """Human-readable Trigger facet from the change/lifecycle signal, if active.

    Names the proximate change that set the incident off — the rolling
    component(s) and any Helm revision — so the ``platform_lifecycle_change``
    headline can state WHAT triggered the disruption instead of leaving it
    implicit. Empty when no lifecycle signal is active."""
    if not lifecycle or not lifecycle.get("active"):
        return ""
    components = [str(c) for c in (lifecycle.get("components") or []) if c]
    parts: list[str] = []
    if components:
        parts.append("rollout/upgrade on " + ", ".join(components))
    helm = lifecycle.get("helm")
    if helm:
        helm_note = (
            ", ".join(str(h) for h in helm)
            if isinstance(helm, (list, tuple))
            else str(helm)
        )
        parts.append(f"Helm: {helm_note}")
    return "; ".join(parts)

# R1 (node_kubelet_pressure) HARD node-condition tokens: an actual kubelet/node
# resource condition or eviction. These are what make "the node is crushing its
# tenants" a defensible ROOT CAUSE. The family's OTHER keywords ("kubelet",
# "device plugin") are SOFT co-occurrence tokens that fire constantly during an
# unrelated GPU-Operator rollout (the device-plugin DaemonSet restarts, kubelet
# is mentioned) — they must NOT, on their own, let a blast radius force node
# pressure to HIGH. A genuine node-pressure incident always carries a hard token.
_NODE_CONDITION_TOKENS = (
    "diskpressure",
    "disk pressure",
    "memorypressure",
    "memory pressure",
    "pidpressure",
    "pid pressure",
    "node pressure",
    "node condition",
    "evict",
)


def _node_condition_present(
    results: list[CollectorResult], *, eligible_evidence_ids: set[str] | None = None
) -> bool:
    """True when a real node-condition/eviction signal is present.

    P3: the R1 blast force-high must be backed by an ACTUAL node condition, not
    the soft co-occurrence tokens ("kubelet", "device plugin") a subsystem's
    rollout emits. The naive approach — substring-scanning the collector text —
    is defeated because the kubernetes collector embeds the RAW node object in
    ``details["queries"]``, and a HEALTHY node object still literally contains
    "DiskPressure"/"MemoryPressure" types and "kubelet has no disk pressure"
    messages. Rank only the collector's scoped artifacts instead. A
    ``node_conditions`` detail is a useful current-state snapshot, but cannot
    establish that a resolved historical incident was caused by pressure that
    happens to exist now. Incident-window Warning events and bounded Prometheus
    predicates keep this force-high gate on the same temporal contract as every
    other RCA support link.
    """
    for r in results:
        if not _collector_is_evidence(r):
            continue
        agent = getattr(r, "agent", "")
        if agent == "kubernetes":
            # ``_result_text`` excludes broad current Node snapshots once the
            # collector publishes structured observations.
            if _keyword_hits(
                _result_text(r, eligible_evidence_ids=eligible_evidence_ids),
                list(_NODE_CONDITION_TOKENS),
            )[0]:
                return True
        elif agent == "prometheus":
            # Prometheus carries no raw node object. Its metric-LABEL identity is
            # value-blind (a healthy node's kube_node_status_condition{condition=
            # "MemoryPressure"} series has the label but VALUE 0), so those label
            # literals are pruned from _result_text (METADATA_VALUE_KEYS subtree
            # drop). A hit here therefore comes from the collector's own SUMMARY
            # (e.g. "MemoryPressure=true"), which is a real, negation-aware signal.
            if _keyword_hits(
                _result_text(r, eligible_evidence_ids=eligible_evidence_ids),
                list(_NODE_CONDITION_TOKENS),
            )[0]:
                return True
    return False


@dataclass
class RankedCause:
    family: str
    confidence: str
    score: float
    rationale: list[str] = field(default_factory=list)
    evidence_agents: list[str] = field(default_factory=list)
    # Multi-axis facets (the (Locus, Nature, Trigger) frame). The `family` stays
    # the headline label; these annotate WHERE (subsystem/Locus), WHAT KIND
    # (nature: fault / saturation / lifecycle_change / observability), and WHAT
    # SET IT OFF (trigger: the proximate change, when known). subsystem/nature are
    # intrinsic to the family and auto-filled in __post_init__ so every
    # construction site (ranker + pipeline promotions) carries them; trigger is
    # dynamic and set by the ranker from the lifecycle/change signal when present.
    subsystem: str = ""
    nature: str = ""
    trigger: str = ""
    # Open-world candidates keep a concrete mechanism separate from the broad
    # catalog family.  Existing callers can ignore these additive fields.
    mechanism: str = ""
    mechanism_fingerprint: str = ""
    hypothesis_id: str = ""
    novelty: str = "catalog"
    broad_family: str = ""
    support_evidence_ids: list[str] = field(default_factory=list)
    contradiction_evidence_ids: list[str] = field(default_factory=list)
    rank_basis: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.subsystem or not self.nature:
            sub, nat = _family_facets(self.family)
            self.subsystem = self.subsystem or sub
            self.nature = self.nature or nat

    def as_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "confidence": self.confidence,
            "score": round(self.score, 2),
            "rationale": self.rationale,
            "evidence_agents": self.evidence_agents,
            "subsystem": self.subsystem,
            "nature": self.nature,
            "trigger": self.trigger,
            "mechanism": self.mechanism,
            "mechanism_fingerprint": self.mechanism_fingerprint,
            "hypothesis_id": self.hypothesis_id,
            "novelty": self.novelty,
            "broad_family": self.broad_family,
            "supporting_evidence_ids": self.support_evidence_ids,
            "contradicting_evidence_ids": self.contradiction_evidence_ids,
            "rank_basis": self.rank_basis,
        }


def novel_family_slug(mechanism: str) -> tuple[str, str]:
    """Return a deterministic public family and stable mechanism fingerprint.

    The LLM never supplies a TypeQL type or a final slug.  Normalising the
    mechanism here prevents spelling variants from producing unstable API
    values and the fingerprint prevents collisions after truncation.
    """
    canonical = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", mechanism).casefold()).strip()
    # The public slug remains ASCII for downstream metrics and TypeQL values,
    # while the fingerprint deliberately uses the Unicode canonical mechanism.
    # Korean/Japanese/etc. therefore share a readable `mechanism` prefix but
    # never collapse into one cause family.
    ascii_hint = unicodedata.normalize("NFKD", canonical).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "_", ascii_hint).strip("_") or "mechanism"
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
    return f"novel_{slug[:42].rstrip('_')}_{fingerprint}"[:64], fingerprint


def merge_open_world_candidates(
    known: list[RankedCause],
    ledger: object,
    *,
    fact_groups: dict[str, str] | None = None,
    enabled: bool = False,
) -> list[RankedCause]:
    """Merge only evidence-gated novel hypotheses into the ranked list.

    A numeric magic score is deliberately avoided.  The score is derived from
    corroborating independent facts and is only a compatibility tie-breaker;
    ``rank_basis`` carries the real adjudication explanation.
    """
    if not enabled or not isinstance(ledger, list):
        return known
    groups = fact_groups or {}
    novel: list[RankedCause] = []
    for item in ledger:
        if not isinstance(item, dict) or str(item.get("status") or "") != "supported":
            continue
        family = str(item.get("family") or "").strip()
        if family in FAMILIES:
            continue
        mechanism = str(item.get("mechanism") or item.get("statement") or "").strip()
        # An investigator can cite the same response-local E-id more than once
        # while revising a hypothesis.  Citations are references, not separate
        # observations, so preserve their first occurrence only.  More
        # importantly, several different query cards can expose the same
        # underlying telemetry plane; their number must not improve an
        # open-world candidate's rank over independently observed evidence.
        support = list(
            dict.fromkeys(_fact_ids(item.get("support_evidence_ids") or item.get("evidence_for")))
        )
        contradict = _fact_ids(
            item.get("contradiction_evidence_ids") or item.get("evidence_against")
        )
        if not mechanism or not support or contradict:
            continue
        # Evidence IDs are labels, not provenance.  Treating an unknown E-id as
        # its own independent source would let a hallucinated pair (E01, E02)
        # satisfy corroboration.  The pipeline supplies this map from the
        # blackboard only after resolving each fact to a response artifact.
        if not groups or any(fact_id not in groups for fact_id in support):
            continue
        independent = {groups[fact_id] for fact_id in support}
        if len(independent) < 2:
            continue
        slug, fingerprint = novel_family_slug(mechanism)
        confidence = "high" if len(independent) >= 3 else "medium"
        novel.append(
            RankedCause(
                family=slug,
                confidence=confidence,
                # Corroboration strength is the number of independent
                # telemetry planes, not the number of query replicas from one
                # plane.  Keeping ``len(support)`` in this score let an LLM
                # promote a candidate merely by repeatedly citing Loki (or
                # several views of the Kubernetes API).
                score=float(len(independent) * 3),
                rationale=[mechanism],
                evidence_agents=sorted(independent),
                mechanism=mechanism,
                mechanism_fingerprint=fingerprint,
                hypothesis_id=str(item.get("id") or ""),
                novelty="open_world",
                broad_family=family,
                support_evidence_ids=support,
                contradiction_evidence_ids=contradict,
                rank_basis=[
                    f"{len(independent)} independent source groups",
                    f"{len(support)} distinct supporting evidence IDs",
                    "discriminating hypothesis marked supported",
                ],
            )
        )
    if not novel:
        return known
    merged = [*known, *novel]
    merged.sort(
        key=lambda candidate: (
            candidate.confidence == "high",
            candidate.novelty == "catalog" and any(
                "signature" in str(reason).lower() or "xid" in str(reason).lower()
                for reason in candidate.rationale
            ),
            not candidate.contradiction_evidence_ids,
            candidate.score,
        ),
        reverse=True,
    )
    return merged[: max(3, len(known))]


def _fact_ids(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


@dataclass
class _Score:
    points: float = 0.0
    rationale: list[str] = field(default_factory=list)
    agents: set[str] = field(default_factory=set)
    force_high: bool = False


def rank_root_cause_candidates(
    target: AnalysisTarget,
    results: list[CollectorResult],
    occurrence_count: int = 0,
    top_n: int = 3,
    kg_blast_radius: int = 0,
    priors: dict[str, float] | None = None,
    component_family: str = "",
    component: str = "",
    depends_on_chain: list[str] | None = None,
    lifecycle: dict[str, Any] | None = None,
    graph_candidate_counts: dict[str, int] | None = None,
    eligible_evidence_ids: set[str] | None = None,
) -> list[RankedCause]:
    """Rank failure families for THIS incident from collector evidence.

    ``component_family`` / ``component`` / ``depends_on_chain`` carry the
    *topology* signal the planner already resolved (``component_for_target``):
    when the alert TARGET itself IS a known platform component, its curated
    family is a topology FACT (WHO the alert is about), not a keyword guess. It
    is injected as a first-class candidate so a keyword-only node/workload match
    cannot bury the real subsystem — while an exact dispositive signature (XID /
    known-issue) still overrides later via ``_promote_signature_cause``.

    ``lifecycle`` carries the Nature axis: when the change collector shows the
    implicated component (or its depends_on chain) is mid-rollout / upgrading,
    the disruption is EXPECTED, not a fault — the ``platform_lifecycle_change``
    family leads and node-pressure blast is not force-flagged. An empty/absent
    ``lifecycle`` leaves ranking unchanged (backward compatible).
    """
    top_n = max(1, top_n)
    text_by_agent = {
        r.agent: _result_text(r, eligible_evidence_ids=eligible_evidence_ids)
        for r in results
    }
    status_by_agent = {r.agent: r.status for r in results}
    blast, blast_agents = _kg_blast_radius(results)
    # TypeDB topology is a current/reference graph, not an incident-window
    # observation.  It can guide collection and explain possible scope, but
    # must not turn a single live condition into a HIGH historical RCA.  Keep
    # the argument for API compatibility while deliberately not promoting it
    # into the causal ranking path.
    _ = kg_blast_radius

    scores = {fam: _Score() for fam in FAMILIES}
    for fam, (canonical, agents, keywords) in _FAMILY_RULES.items():
        s = scores[fam]
        for agent in agents:
            text = text_by_agent.get(agent, "")
            if not text:
                continue
            hits = sorted(set(_keyword_hits(text, list(keywords))[0]))
            if not hits:
                continue
            weight = 2.0 if agent == canonical else 1.0
            # cap per-agent contribution so one verbose log can't dominate
            s.points += weight * min(len(hits), 3)
            s.agents.add(agent)
            s.rationale.append(f"{agent} evidence matched {', '.join(hits[:3])}")

    _apply_bonuses(
        scores,
        blast,
        blast_agents,
        occurrence_count,
        component_family,
        lifecycle_active=bool(lifecycle and lifecycle.get("active")),
        node_condition=_node_condition_present(
            results, eligible_evidence_ids=eligible_evidence_ids
        ),
    )

    # Topology identity: the alert TARGET itself IS a known platform component.
    # Its curated family leads over keyword-only competitors and its depends_on
    # chain names the subsystem to inspect (e.g. runai-container-toolkit → the
    # NVIDIA GPU Operator stack), even when every collector came back empty.
    _apply_component_identity(scores, component_family, component, depends_on_chain or [])

    # Nature axis: a rollout/upgrade in progress on the implicated component is a
    # lifecycle EVENT, not a fault. Applied AFTER component identity so it floors
    # above the (already boosted) subsystem-fault family.
    _apply_lifecycle_gate(scores, lifecycle)

    # Optional feedback-derived priors nudge a family only after this incident
    # has a typed, scoped observation for that family's own collector.  A
    # similar incident's vote must not amplify a legacy prose summary (or a
    # historical memory card) into a current causal claim.  Priors still never
    # create a candidate from nothing.
    if priors:
        for fam, s in scores.items():
            factor = priors.get(fam)
            if (
                factor is not None
                and s.points > 0
                and _has_typed_incident_observation(target, results, s.agents)
            ):
                s.points *= factor
                s.rationale.append(f"feedback prior adjusted score x{factor:.2f}")

    # The graph is allowed to corroborate a symptom that was already matched in
    # THIS run, never to create a high-confidence cause from historical memory.
    # A cap keeps a broad catalog from drowning out live collector evidence.
    for family, count in (graph_candidate_counts or {}).items():
        score = scores.get(family)
        # The graph corroborates an observation that this run already matched;
        # it is not an observation source itself and must never materialize a
        # candidate from historical/ontology context alone.
        if score is None or count <= 0 or score.points <= 0:
            continue
        bonus = min(2.0, float(count))
        score.points += bonus
        score.rationale.append(f"ontology matched {int(bonus)} live symptom signal(s)")

    ranked = [
        RankedCause(
            family=fam,
            score=s.points,
            rationale=s.rationale,
            evidence_agents=sorted(s.agents),
            confidence=_confidence(fam, s, status_by_agent),
        )
        for fam, s in scores.items()
        if s.points > 0
    ]
    # Trigger facet: name the proximate change on the lifecycle candidate (its
    # nature is a rollout/upgrade, so the Trigger is that change). Subsystem/nature
    # are auto-filled per family in RankedCause.__post_init__.
    trigger = _lifecycle_trigger(lifecycle)
    if trigger:
        for c in ranked:
            if c.family == _LIFECYCLE_FAMILY:
                c.trigger = trigger
    ranked.sort(key=lambda c: c.score, reverse=True)

    # R6 evidence gate: topology/KG identity can focus investigation but cannot
    # establish a root cause by itself. A final family needs at least one real
    # collector observer; synthetic agents remain visible on the candidate for
    # follow-up planning without allowing it to bypass insufficient-evidence.
    top_has_live_observer = bool(
        ranked and (set(ranked[0].evidence_agents) - _SYNTHETIC_AGENTS)
    )
    if not ranked or ranked[0].score < _FLOOR or not top_has_live_observer:
        gate = _insufficient(results, status_by_agent)
        return [gate, *ranked][:top_n]
    return ranked[:top_n]


def _apply_bonuses(
    scores: dict[str, _Score],
    blast: int,
    blast_agents: set[str],
    occurrence_count: int,
    component_family: str = "",
    lifecycle_active: bool = False,
    node_condition: bool = True,
) -> None:
    node = scores["node_kubelet_pressure"]
    startup = scores["workload_startup_error"]
    quota = scores["runai_scheduling_quota"]
    control = scores["runai_control_plane_error"]

    # R1: node pressure with blast radius across >=2 workloads on the node.
    # BUT when the alert TARGET itself IS a non-node platform component, OR a
    # rollout/upgrade is in progress, that explains the multi-pod impact — a stuck
    # DaemonSet / rolling operand touches many nodes/pods without the NODE being
    # under pressure. In those cases the blast bonus must NOT inflate or force
    # node_kubelet_pressure high (this exact misfire ranked a gpu-operator upgrade
    # as "node kubelet pressure, HIGH").
    #
    # P3: the blast force-high ALSO requires a genuine node-CONDITION signal
    # (DiskPressure/MemoryPressure/PIDPressure/eviction). The family can score on
    # SOFT tokens ("kubelet", "device plugin") that a subsystem's coordinated
    # DaemonSet rollout emits without any node condition; a blast radius must not
    # turn that soft co-occurrence into a forced HIGH when the node itself reports
    # no pressure — that's the single-owner/subsystem multi-node rollout case that
    # neither component-identity nor a (possibly undetected) lifecycle signal caught.
    node_is_identified = component_family in ("", "node_kubelet_pressure")
    if (
        node.points > 0
        and blast >= 2
        and node_is_identified
        and not lifecycle_active
        and node_condition
    ):
        node.points += 3.0
        node.agents.update(blast_agents)
        node.force_high = True
        node.rationale.append(f"blast radius: {blast} workloads affected on the same node")
    # R4: startup failure is more likely when the control plane is quiet.
    if startup.points > 0 and control.points == 0:
        startup.points += 1.0
        startup.rationale.append("control-plane logs quiet — points to a workload-local fault")
    # quota signal is stronger when a queue/project is actually in play (already
    # in the matched text); nudge so a lone keyword doesn't tie a real one.
    if quota.points > 0 and any(a in quota.agents for a in ("prometheus", "runai")):
        quota.points += 0.5
    # flapping favours cycling failure modes (node eviction / crashloop).
    if occurrence_count > 1:
        for s in (node, startup):
            if s.points > 0:
                s.points += 0.5
                s.rationale.append("alert is flapping (grouped occurrences) — cycling workload")


# The alert TARGET being a known platform component is a topology fact, not a
# keyword guess. This weight lets its curated family lead a keyword-only node or
# workload match, yet stays low enough that a strongly corroborated (>=2 agents)
# error family, or an exact dispositive signature applied AFTER ranking (XID /
# known-issue via _promote_signature_cause), can still win.
_COMPONENT_IDENTITY_WEIGHT = 4.0

# Synthetic agents are topology/KG facts injected by the ranker itself; they do
# not independently OBSERVE a failure, so they must not count as one of the
# corroborating evidence sources required for HIGH confidence.
# typedb is the concrete graph adapter name used by older/result-level
# integrations; it carries topology/blast context, not a live fault observation.
_SYNTHETIC_AGENTS = {"topology", "knowledge-graph", "typedb"}


def _independent_observer_groups(agents: set[str]) -> set[str]:
    """Collapse collectors that read the same telemetry plane.

    The deterministic catalog ranker predates the fact-level blackboard and
    historically used collector names as corroboration units. That let the
    change collector and the Kubernetes collector satisfy a two-observer HIGH
    gate even though both read the Kubernetes API. Keep agent names in
    operator-facing candidate output, but use the fact-level source-group
    contract for confidence and corroboration.
    """
    return {
        source_independence_group(agent)
        for agent in agents
        if agent not in _SYNTHETIC_AGENTS
    }


def _apply_component_identity(
    scores: dict[str, _Score],
    family: str,
    component: str,
    chain: list[str],
) -> None:
    """Elevate the family named by the alert target's component identity.

    ``family`` is ``component_entry['family']`` from runai_architecture.yaml
    (already resolved by the planner). Adds a ``topology`` agent so the candidate
    clears the evidence floor from a real, non-keyword source, and records the
    depends_on check order so the report points at the right subsystem.

    Leadership rule: the identity must out-rank any family that is NOT
    corroborated by >=2 real evidence agents (a keyword-only node/workload guess),
    yet concede to a family that IS multi-source corroborated. So we raise it a
    fixed step, then floor it just above the strongest weakly-corroborated rival.
    """
    if not family or family not in scores:
        return
    s = scores[family]
    s.agents.add("topology")
    # "Real" corroboration = distinct evidence agents, excluding the synthetic
    # topology/KG signals that don't independently observe a failure.
    strongest_weak_rival = max(
        (
            other.points
            for fam, other in scores.items()
            if fam != family and len(_independent_observer_groups(other.agents)) < 2
        ),
        default=0.0,
    )
    s.points = max(s.points + _COMPONENT_IDENTITY_WEIGHT, strongest_weak_rival + 1.0)
    where = f"alert target IS platform component {component}" if component else (
        "alert target is a known platform component"
    )
    if len(chain) > 1:
        where += f" → check depends_on: {' → '.join(chain)}"
    s.rationale.append(f"{where} ⇒ {family}")


_LIFECYCLE_FAMILY = "platform_lifecycle_change"


def _apply_lifecycle_gate(scores: dict[str, _Score], lifecycle: dict[str, Any] | None) -> None:
    """Lead the lifecycle family when the implicated component is mid-rollout.

    ``lifecycle`` (from the change collector, resolved in the pipeline) carries:
      - ``active``: a rollout/upgrade touching the implicated component or a
        component in its depends_on chain is in progress,
      - ``components``: the names of those rolling components (for the rationale),
      - ``target_rollout``: the alert's OWN component is the one rolling out — the
        alert IS about the rollout, which is dispositive (force high),
      - ``helm``: optional Helm-revision note.

    Absent/inactive ``lifecycle`` is a no-op (ranking stays legacy). The ``change``
    collector is a REAL observer, so it counts toward the >=2-agent HIGH gate; but
    with only ``change`` observing, confidence stays medium unless ``target_rollout``
    makes it dispositive. An exact hardware signature (XID) still overrides later
    via ``_promote_signature_cause`` — an upgrade window doesn't excuse a real fault.
    """
    if not lifecycle or not lifecycle.get("active"):
        return
    fam = _LIFECYCLE_FAMILY
    if fam not in scores:
        return
    s = scores[fam]
    s.agents.add("change")
    strongest_weak_rival = max(
        (
            other.points
            for f, other in scores.items()
            if f != fam and len(_independent_observer_groups(other.agents)) < 2
        ),
        default=0.0,
    )
    s.points = max(s.points + _COMPONENT_IDENTITY_WEIGHT, strongest_weak_rival + 1.0)
    components = [c for c in (lifecycle.get("components") or []) if c]
    where = "rollout/upgrade in progress"
    if components:
        where += " on " + ", ".join(components)
    helm = lifecycle.get("helm")
    if helm:
        helm_note = ", ".join(str(h) for h in helm) if isinstance(helm, (list, tuple)) else str(helm)
        where += f"; {helm_note}"
    s.rationale.append(
        f"{where} ⇒ expected disruption, not a fault — "
        "verify the rollout/Helm release completed"
    )
    # The alert's OWN component is the one rolling => the alert IS the rollout.
    if lifecycle.get("target_rollout"):
        s.force_high = True


def _confidence(fam: str, s: _Score, status_by_agent: dict[str, str]) -> str:
    # HIGH requires >=2 independent telemetry groups that genuinely observed
    # the failure. Synthetic topology/KG context can floor a score but cannot
    # unlock HIGH, and two collectors reading the Kubernetes API count once.
    real_source_groups = len(_independent_observer_groups(s.agents))
    if s.force_high or (s.points >= _HIGH and real_source_groups >= 2):
        level = 2  # high
    elif s.points >= _MED or s.agents:
        level = 1  # medium
    else:
        level = 0  # low
    # missing-data penalty: canonical source unavailable -> downgrade one level.
    canonical = _FAMILY_RULES[fam][0]
    if status_by_agent.get(canonical) == "unavailable":
        level = max(0, level - 1)
    return _CONF_ORDER[level]


def _insufficient(
    results: list[CollectorResult], status_by_agent: dict[str, str]
) -> RankedCause:
    unavailable = sorted(a for a, st in status_by_agent.items() if st == "unavailable")
    ok = sorted(a for a, st in status_by_agent.items() if st == "ok")
    rationale = [
        "No failure family cleared the confirmation threshold from a corroborating "
        "source. Lower-confidence candidates remain working hypotheses for follow-up (R6).",
    ]
    if unavailable:
        rationale.append(f"Evidence gaps: {', '.join(unavailable)} unavailable.")
    confidence = "medium" if len(ok) >= 2 else "low"
    return RankedCause(
        family=INSUFFICIENT,
        confidence=confidence,
        score=0.0,
        rationale=rationale,
        evidence_agents=ok,
    )


# The kubernetes collector embeds the RAW node/pod objects it fetched under
# ``details["queries"]`` (and mirrors the same dict into its artifact ``result``).
# A perfectly HEALTHY node object still literally contains the failure vocabulary
# — condition type "DiskPressure"/"MemoryPressure" (status False) and messages
# like "kubelet has no disk pressure" — so a substring keyword scan scored
# ``node_kubelet_pressure`` (and matched the curated "Node Disk Pressure" symptom)
# on nodes that had NO pressure at all (the recurring "왜 다 False인데 아직도 그게
# 있다고 하냐" misfire). The collector already distils its real signal into
# structured keys (``node_conditions`` is abnormal-only, ``warning_events``,
# ``pod_logs``, ``container_diagnostics``, …), so we drop the raw ``queries``
# duplicate from EVERY keyword-scan text (both the family ranker here and the
# signature/symptom matcher in pipeline._evidence_leaf_text — they must share one
# policy or the leak reappears in whichever path is missed). loki/prometheus/runai
# put their PRIMARY signal in ``queries``, so the drop is scoped to kubernetes.
COLLECTOR_TEXT_DROP_KEYS: dict[str, frozenset[str]] = {
    "kubernetes": frozenset({"queries"}),
}
_RANKING_TEXT_DROP_KEYS = COLLECTOR_TEXT_DROP_KEYS  # backward-compatible alias

# A timestamped Pod-log line proves the line existed, not that every failure
# token inside it is an active condition. Kubernetes commonly logs recovery
# status alongside a historic reason ("healthy after OOMKilled") and probes
# often emit negative checks ("OOMKilled=false"). The generic keyword
# negation helper intentionally permits nuanced prose; at this evidence
# boundary be conservative instead: a normal/recovery-valued raw line cannot
# substantiate a root-cause family. Structured Event reasons remain available
# below when Kubernetes itself reports the positive reason.
_KUBERNETES_NON_CAUSAL_SIGNAL_RE = re.compile(
    r"\b(?:no|not|without|none|zero|false|healthy|normal|nominal|stable|ready|"
    r"recovery|recovering|recovered|resolved|cleared|fixed|remediated|success|"
    r"succeeded)\b|(?:없음|정상|복구|해결|미발생|아님)"
)
_PODGROUP_GPU_SHORTAGE_RE = re.compile(
    r"\bnvidia\.com/(?:gpu|mig-[a-z0-9.-]+)\b|"
    r"\binsufficient\s+(?:available\s+)?gpus?\b|"
    r"\b(?:did(?:\s+not|n't)|does(?:\s+not|n't))\s+have\s+enough\s+"
    r"resources?\s*:\s*gpus?\b",
    re.IGNORECASE,
)


def _kubernetes_signal_is_positive(value: object) -> bool:
    """Whether a raw Kubernetes value can carry a live failure signal."""
    text = " ".join(str(value or "").split())
    return bool(text) and _KUBERNETES_NON_CAUSAL_SIGNAL_RE.search(text.casefold()) is None


def _kubernetes_semantic_artifact_text(art: object) -> str:
    """Keep only value-aware positive signals from Pod logs and Warning Events."""
    payload = getattr(art, "result", None)
    if not isinstance(payload, Mapping):
        return ""
    artifact_type = str(getattr(art, "type", ""))
    parts: list[str] = []
    if artifact_type == "kubernetes_pod_log":
        entries = payload.get("sample_entries")
        if not isinstance(entries, list):
            entries = payload.get("lines") if isinstance(payload.get("lines"), list) else []
        for entry in entries:
            line = entry.get("line") if isinstance(entry, Mapping) else entry
            if _kubernetes_signal_is_positive(line):
                parts.append(str(line))
    elif artifact_type == "kubernetes_warning_events":
        events = payload.get("events")
        for event in events if isinstance(events, list) else []:
            if not isinstance(event, Mapping):
                continue
            # A Normal Event is never a failure signal. The collector normally
            # removes these earlier, but keep ranking fail-closed for adapters
            # and test fixtures that hand us an unfiltered response.
            event_type = str(event.get("type") or "").strip().casefold()
            if event_type and event_type != "warning":
                continue
            reason = event.get("reason")
            if _kubernetes_signal_is_positive(reason):
                parts.append(str(reason))
            message = event.get("message")
            if _kubernetes_signal_is_positive(message):
                parts.append(str(message))
            # PodGroup is a structured Run:ai scheduling identity, not a word
            # found in a query. When that exact target Event also states a GPU
            # shortage, expose the typed meaning so Run:ai quota/scheduler can
            # rank alongside (and ahead of) generic kube-scheduler placement.
            if (
                event.get("target_identity_verified") is True
                and str(event.get("kind") or "").casefold() == "podgroup"
                and _PODGROUP_GPU_SHORTAGE_RE.search(str(message or ""))
            ):
                parts.append("podgroup requested gpus")
    return " ".join(parts)


def _prometheus_semantic_artifact_text(art: object) -> str:
    """Map verified typed capacity predicates to their scheduling meaning.

    Query names and JSON keys are normally excluded from ranking on purpose.
    A positive, scoped ``runai_*_capacity_gap`` observation is different: the
    collector has already verified target labels, sample timestamps and a
    strictly positive requested-minus-allocated value.  Expose that typed
    truth as canonical value text without reopening generic metric-name or
    query-string keyword matching.
    """
    payload = getattr(art, "result", None)
    if not isinstance(payload, Mapping):
        return ""
    observation = payload.get("observation")
    if not isinstance(observation, Mapping):
        return ""
    if (
        str(observation.get("polarity") or "") != "present"
        or str(observation.get("coverage") or "") != "scoped"
    ):
        return ""
    predicate = str(observation.get("predicate") or "").strip().casefold()
    if predicate in {
        "metric:runai_queue_capacity_gap",
        "metric:runai_project_capacity_gap",
    }:
        return "runai quota over quota requested gpus capacity gap"
    return _leaf_text(payload)


def _artifact_ranking_value_text(
    art: object, drop_keys: "frozenset[str] | set[str] | None"
) -> str:
    if str(getattr(art, "type", "")) in {
        "kubernetes_pod_log",
        "kubernetes_warning_events",
    }:
        return _kubernetes_semantic_artifact_text(art)
    if (
        str(getattr(art, "source", "")).casefold() == "prometheus"
        and str(getattr(art, "type", "")) == "promql_signal"
    ):
        return _prometheus_semantic_artifact_text(art)
    result = getattr(art, "result", None)
    return _leaf_text(result, drop_keys) if result is not None else ""


def _result_text(
    result: CollectorResult, *, eligible_evidence_ids: set[str] | None = None
) -> str:
    if not _collector_is_evidence(result):
        return ""
    drop_keys = _RANKING_TEXT_DROP_KEYS.get(getattr(result, "agent", ""))
    artifacts = list(result.artifacts)
    # New collectors publish explicit polarity/coverage observations. Once a
    # collector has that contract, never fall back to its broad summary/details
    # blob: it can contain current snapshots, query text or tail-limited logs.
    # Only a positive, fully scoped card is eligible for deterministic family
    # ranking. Legacy collectors keep the prior compatibility path until they
    # publish structured observations.
    structured = [art for art in artifacts if _artifact_observation(art) is not None]
    if structured:
        parts: list[str] = []
        for art in structured:
            if not _artifact_is_evidence(art, eligible_evidence_ids=eligible_evidence_ids):
                continue
            semantic_kubernetes_card = str(getattr(art, "type", "")) in {
                "kubernetes_pod_log",
                "kubernetes_warning_events",
            }
            if art.summary and (
                not semantic_kubernetes_card or _kubernetes_signal_is_positive(art.summary)
            ):
                parts.append(art.summary)
            parts.append(_artifact_ranking_value_text(art, drop_keys))
        return " ".join(parts).lower()

    parts = [result.summary or ""]
    for art in artifacts:
        if not _artifact_is_evidence(art):
            continue
        if art.summary:
            parts.append(art.summary)
        parts.append(_artifact_ranking_value_text(art, drop_keys))
    if result.details:
        parts.append(_leaf_text(result.details, drop_keys))
    return " ".join(parts).lower()


def _collector_is_evidence(result: CollectorResult) -> bool:
    return result.status in ("ok", "partial")


def _artifact_is_evidence(
    art: object, *, eligible_evidence_ids: set[str] | None = None
) -> bool:
    if getattr(art, "status", "") not in ("ok", "partial"):
        return False
    observation = _artifact_observation(art)
    if observation is None:
        return True
    scoped_positive = (
        str(observation.get("polarity") or "") == "present"
        and str(observation.get("coverage") or "") == "scoped"
    )
    if not scoped_positive:
        return False
    # The pipeline calculates a stricter target/time/run eligibility verdict
    # after normalizing artifacts onto the blackboard.  A typed card can be
    # scoped for its own query yet still belong to a different entity or a
    # post-resolution epilogue.  Once that verdict is available, the catalog
    # ranker must not reintroduce the card through its raw text scan.
    return eligible_evidence_ids is None or str(getattr(art, "evidence_id", "")) in eligible_evidence_ids


def _artifact_observation(art: object) -> dict[str, object] | None:
    result = getattr(art, "result", None)
    if not isinstance(result, dict):
        return None
    observation = result.get("observation")
    return observation if isinstance(observation, dict) else None


_ALERT_XID_EVIDENCE_RE = re.compile(r"\bxid\s*(?:\([^)]*\))?\s*[:=]?\s*\d{1,4}\b", re.I)


def _artifact_family_semantics(art: object) -> tuple[str, str, str]:
    """Return ``(agent, predicate, semantic_text)`` for claim-level gates."""
    observation = _artifact_observation(art) or {}
    agent = str(getattr(art, "agent", "") or "").strip().casefold()
    predicate = str(observation.get("predicate") or "").strip().casefold()
    summary = str(getattr(art, "summary", "") or "")
    highlights = " ".join(
        str(item) for item in (getattr(art, "highlights", None) or [])
    )
    drop_keys = _RANKING_TEXT_DROP_KEYS.get(agent)
    semantic_value = _artifact_ranking_value_text(art, drop_keys)
    return (
        agent,
        predicate,
        " ".join((predicate, summary, highlights, semantic_value)).casefold(),
    )


def _artifact_is_relevant_to_family(family: str, art: object) -> bool:
    """Whether the card's predicate/value is about ``family`` at all.

    This deliberately ignores polarity.  Support and contradiction apply their
    own polarity checks around this predicate-level relevance test.
    """
    rule = _FAMILY_RULES.get(family)
    observation = _artifact_observation(art)
    if rule is None or observation is None:
        return False
    agent, predicate, semantic_text = _artifact_family_semantics(art)
    if agent == "alert":
        if predicate == "alert_signature:nvidia_xid":
            return (
                family == "gpu_hardware_error"
                and _ALERT_XID_EVIDENCE_RE.search(semantic_text) is not None
            )
        return predicate == f"alert_signature:{family}"

    _canonical, allowed_agents, keywords = rule
    if agent not in {str(item).casefold() for item in allowed_agents}:
        return False
    # A scoped absence naturally says "no/false" and therefore cannot use the
    # normal negation-aware keyword matcher.  At this layer we only establish
    # predicate relevance; the support path below still applies the stricter
    # value-aware matcher before accepting a positive claim.
    return any(str(keyword).casefold() in semantic_text for keyword in keywords)


def artifact_supports_family(family: str, art: object) -> bool:
    """Whether one typed positive artifact actually supports ``family``.

    Target/time eligibility answers *where and when* an observation happened;
    it does not answer *what proposition* the observation establishes.  Keep
    this second gate beside the catalog ranker's value-aware text projection so
    ranking, self-check, and the output harness share the same semantics.  In
    particular, a Kubernetes ``OOMKilled`` observation must not support
    ``k8s_scheduling_error`` merely because Kubernetes is that family's
    canonical collector.

    Alert payloads are admitted only through an explicit, auditable signature
    predicate.  Today NVIDIA XID is the dispositive alert-only signature; broad
    alert prose is intentionally not a generic bypass for catalog families.
    """
    observation = _artifact_observation(art)
    if observation is None or not _artifact_is_relevant_to_family(family, art):
        return False
    if (
        str(observation.get("polarity") or "").strip().casefold() != "present"
        or str(observation.get("coverage") or "").strip().casefold() != "scoped"
    ):
        return False

    rule = _FAMILY_RULES[family]
    agent, predicate, semantic_text = _artifact_family_semantics(art)

    if agent == "alert":
        if predicate == "alert_signature:nvidia_xid":
            return (
                family == "gpu_hardware_error"
                and _ALERT_XID_EVIDENCE_RE.search(semantic_text) is not None
            )
        if predicate != f"alert_signature:{family}":
            return False
        return bool(_keyword_hits(semantic_text, list(rule[2]))[0])

    _canonical, allowed_agents, keywords = rule
    if agent not in {str(item).casefold() for item in allowed_agents}:
        return False
    return bool(_keyword_hits(semantic_text, list(keywords))[0])


def artifact_contradicts_family(family: str, art: object) -> bool:
    """Accept only a scoped absence of a predicate relevant to ``family``.

    A positive observation from another subsystem can coexist with the proposed
    cause; it is not a falsifier merely because an LLM linked it as one.
    """
    observation = _artifact_observation(art)
    return bool(
        observation is not None
        and str(observation.get("polarity") or "").strip().casefold() == "absent"
        and str(observation.get("coverage") or "").strip().casefold() == "scoped"
        and _artifact_is_relevant_to_family(family, art)
    )


def _has_typed_incident_observation(
    target: AnalysisTarget,
    results: list[CollectorResult],
    candidate_agents: set[str],
) -> bool:
    """Whether feedback has a scoped observation from this incident to nudge.

    The feedback channel is derived from prior incident votes/comments.  It can
    shape the ranking of a verified observation, but neither a compatibility
    summary nor a card explicitly marked as a historical prior is enough to
    make that feedback relevant to the current incident.
    """
    # A prior is deliberately weaker than live telemetry.  It may only adjust
    # a score when a typed observation names this incident's resource and
    # actually occurred inside the alert interval.  Checking just the nested
    # polarity/coverage envelope let a stale query result (or another Pod's
    # result returned by a broad query) amplify the current candidate.
    fired_at = str(target.fired_at or "").strip()
    resolved_at = str(target.resolved_at or "").strip()
    entities = _target_entity_tokens(target)
    if not (fired_at and resolved_at and entities):
        return False

    from app.services.evidence_blackboard import EvidenceEligibility, normalize_artifact

    context = {
        "window_start": fired_at,
        "window_end": resolved_at,
        "entities": entities,
    }
    for result in results:
        if result.agent not in candidate_agents:
            continue
        for card in result.artifacts:
            observation = _artifact_observation(card)
            if observation is None:
                continue
            payload = getattr(card, "result", None)
            if (
                observation.get("historical_prior") is True
                or isinstance(payload, dict)
                and payload.get("historical_prior") is True
            ):
                continue
            # Do not inherit the pipeline target for a feedback gate. A
            # collector must identify the observed entity itself; otherwise a
            # broad namespace/live result can be relabelled as this Pod.
            if not _declares_observed_entity(observation):
                continue
            try:
                fact = normalize_artifact(card, require_typed_observation=True)
            except Exception:  # noqa: BLE001 - malformed evidence cannot ground a prior
                continue
            if EvidenceEligibility.from_fact(fact, context=context).support:
                return True
    return False


def _declares_observed_entity(observation: Mapping[str, object]) -> bool:
    """Whether a typed observation owns its resource identity explicitly."""
    entity = observation.get("observed_entity", observation.get("entity"))
    if isinstance(entity, Mapping):
        return bool(
            str(entity.get("kind") or entity.get("type") or "").strip()
            and str(entity.get("name") or entity.get("id") or "").strip()
        )
    return isinstance(entity, str) and bool(entity.strip())


def _target_entity_tokens(target: AnalysisTarget) -> list[str]:
    """Return the concrete alert identities allowed to ground a prior boost."""
    return [
        f"{field}:{value}"
        for field in (
            "pod",
            "node",
            "workload_name",
            "runai_workload_id",
            "project",
            "queue",
            "namespace",
            "storage_claim",
            "service",
        )
        if (value := str(getattr(target, field, "") or "").strip())
    ]


def _leaf_text(value: Any, drop_keys: "frozenset[str] | set[str] | None" = None) -> str:
    """Match evidence values, not JSON schema/key names.

    ``drop_keys`` prunes whole subtrees whose dict key matches (case-insensitive)
    — used to keep the raw ``queries`` firehose of a collector out of the ranking
    keyword scan while leaving the collector's structured evidence intact."""
    parts: list[str] = []
    drop = {k.lower() for k in drop_keys} if drop_keys else None

    def walk(node: Any, key: str = "") -> None:
        if node is None:
            return
        key_l = key.lower()
        # Prune metadata-key subtrees BEFORE recursing: a metadata key (metric,
        # expr, query, name, ...) can hold a dict/list — e.g. a prometheus series'
        # ``metric`` label set {"condition":"DiskPressure","status":"true"} whose
        # VALUE is 0 (healthy). Checking only at the scalar leaf let those label
        # literals leak and score node_kubelet_pressure on a healthy node. We match
        # RETURNED values, never the query/label identity.
        if key_l in _METADATA_VALUE_KEYS:
            return
        if isinstance(node, dict):
            for child_key, child in node.items():
                if drop and str(child_key).lower() in drop:
                    continue
                walk(child, str(child_key))
        elif isinstance(node, (list, tuple)):
            for child in node:
                walk(child, key)
        elif key_l in {"xid", "xid_code", "nvidia_xid"}:
            parts.append(f"xid {node}")
        elif isinstance(node, (str, int, float, bool)):
            parts.append(str(node))
        else:
            parts.append(str(node))

    walk(value)
    return " ".join(" ".join(parts).split())


def _kg_blast_radius(results: list[CollectorResult]) -> tuple[int, set[str]]:
    best = 0
    agents: set[str] = set()
    for r in results:
        if r.agent in _SYNTHETIC_AGENTS:
            continue
        if not _collector_is_evidence(r):
            continue
        raw = r.details.get("blast_radius_workloads") or r.details.get("kg_blast_radius")
        if raw is None:
            continue
        try:
            blast = int(raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if blast > best:
            best = blast
            agents = {r.agent}
        elif blast == best and blast > 0:
            agents.add(r.agent)
    return best, agents
