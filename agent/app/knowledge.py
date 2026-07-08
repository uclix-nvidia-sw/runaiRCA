from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.bm25 import BM25Index

_FUZZY_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]{2,}")
_CONTRAST_PREFIX_RE = re.compile(
    r"\b(?:but|however|though|yet)\s+(?:now\s+|currently\s+)?(?:[\w\"'-]+\s+){0,4}$"
    r"|(?:지만|하지만)\s*(?:\S+\s+){0,4}$"
)
_POSITIVE_SUFFIX_RE = re.compile(r"^\s*(?:\S+\s+){0,1}(?:true|1|[2-9]\d*)\b")
_POSITIVE_PREFIX_RE = re.compile(r"\b(?:not\s+zero|nonzero)\s+(?:[\w\"'-]+\s+){0,4}$")
_NON_EVIDENCE_PREFIX_RE = re.compile(
    r"(?:\b(?:config\s+key|label\s+key|annotation|dashboard\s+field|column\s+name|"
    r"metric\s+name|helm\s+value|template\s+variable|catalog\s+entry|"
    r"example\s+alert|sample\s+(?:payload|log\s+line)|alert\s+rule\s+name|"
    r"threshold|series\s+name|recording\s+rule\s+example|grafana\s+panel\s+query|"
    r"docs?\s+example|runbook\s+example|prometheus\s+rule\s+expression|"
    r"alert\s+label|schema\s+field|columns?)\b|(?:환경변수|대시보드\s+필드)\b)"
    r".{0,128}$"
)
_NEGATED_PREFIX_RE = re.compile(
    r"\b(?:no|not|without|never)\s+(?:a\s+|an\s+|the\s+)?(?:[\w\"'-]+\s+){0,4}$"
    r"|(?:\b(?:0|zero)\s+(?:[\w\"'-]+\s+){0,4}$)"
    r"|(?:\babsent\s*\(.{0,160}$)"
    r"|(?:\boperator\s+(?:asked\s+whether|prompt)\W+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\b(?:please\s+)?check\s+for\s+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\brunbook\s+says\s+to\s+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\bquestion\W+(?:could\s+this\s+be\s+)?(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\bnext\s+step\s+is\s+to\s+inspect\s+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\bplaybook\s+mentions\s+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\bhypothesis\W+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\btodo\s+check\s+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\btemplate\s+includes\s+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\bsupport\s+case\s+says\s+(?:[\w\"'-]+\s+){0,10}$)"
    r"|(?:\brunbook\s+command\b.{0,96}$)"
    r"|(?:\b(?:config\s+key|label\s+key|annotation|dashboard\s+field|column\s+name|"
    r"metric\s+name|helm\s+value|template\s+variable)\s+(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:(?:환경변수|대시보드\s+필드)\s+(?:\S+\s+){0,4}$)"
    r"|(?:\b(?:resolved|cleared|recovered|remediated|refreshed)\s+"
    r"(?:[\w\"'-]+\s+){0,8}$)"
    r"|(?:\bruled\s+out\s+(?:[\w\"'-]+\s+){0,4}$)"
    r"|(?:\b(?:false\s+alarm|false\s+positive)\s+(?:[\w\"'-]+\s+){0,4}$)"
    r"|(?:\b(?:previously|formerly|historical|historic|past|old|earlier|former|"
    r"stale|archived|yesterday)\s+(?:[\w\"'-]+\s+){0,4}$)"
    r"|(?:\blast\s+(?:week|month)\s+(?:[\w\"'-]+\s+){0,4}$)"
    r"|(?:(?:과거|이전|지난주|예전)\s+(?:\S+\s+){0,4}$)"
)
_NEGATED_SUFFIX_RE = re.compile(
    r"^\s*(?:[\w\"'-]+\s+){0,2}(?:is|are|was|were)?\s*not\s+"
    r"(?:present|seen|observed|reproduced|happening)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,2}(?:is|are|was|were)?\s*not\s+"
    r"(?:exceeded|exhausted|saturated|constrained|blocked)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,2}(?:is|are|was|were)?\s*not\s+"
    r"(?:the\s+)?(?:issue|cause|problem|root\s+cause)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,2}(?:is|are|was|were)?\s*not\s+"
    r"(?:implicated|involved|related)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,2}(?:is|are|was|were)?\s*"
    r"(?:unrelated|excluded)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,2}(?:was|were)?\s*ruled\s+out\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,2}(?:was|were)?\s*"
    r"(?:resolved|cleared|recovered|fixed|remediated|refreshed)\b"
    r"|^\s*(?:is|are|was|were)\s+(?:missing|absent)\b"
    r"|^\s*(?:is|are|was|were)\s+"
    r"(?:healthy|stable|running|ready|reachable|bound|mounted)\b"
    r"|^\s*(?:has|have)\s+(?:plenty|enough)\s+(?:available|free)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,4}"
    r"(?:available|sufficient|reachable|bound|mounted|ready|absent|normal|inactive|ok|nominal|quiet|fine)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,4}"
    r"(?:succeed|succeeds|succeeded|succeeding|healthy|stable|running|completed|cached)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,6}(?:returned|returns)\s+(?:0|zero|no)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,6}no\s+(?:matching\s+)?(?:lines?|series|data)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,6}no\s+lines\s+found\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,6}"
    r"(?:(?:current\s+)?value\s+(?:is\s+)?0|(?:currently\s+)?zero|"
    r"count\s+(?:is\s+)?zero)\b"
    r"|^\s*(?:\S+\s+){0,4}(?:false|0)\b"
    r"|^\s*(?:[\w\"'-]+\s+){0,4}(?:은|는|이|가|도)?\s*"
    r"(?:아님|아니다|없음|없다|관찰되지\s*않음|발생하지\s*않음|"
    r"감지되지\s*않음|확인되지\s*않음|정상|성공|해결됨|복구됨|정상화)"
    r"|^\s*(?:[\w\"'-]+\s+){0,6}"
    r"(?:no\s+evidence|needs?\s+evidence|possible|examples?|during\s+triage|"
    r"before\s+blaming)\b"
    r"|^\s*(?:\S+\s+){0,4}(?:여부\s*확인|확인\s*요청|확인\s*필요|가능성\s*점검)\b"
    r"|^\s*(?:\S+\s+){0,4}(?:현재\s+)?(?:값|카운트|발생)\s*(?:0|없음)\b"
    r"|^\s*(?:\S+\s+){0,4}0\s*(?:건|개)"
    r"|^\s*(?:은|는|이|가|도)?\s*(?:문제|원인|이슈)(?:가|는)?\s*"
    r"(?:아님|아니다|없음|없다)"
)


@dataclass(frozen=True)
class FamilyCatalog:
    families: tuple[str, ...]
    rules: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]]
    hints: tuple[tuple[str, tuple[str, ...]], ...]
    reasons: dict[str, str]


DEFAULT_FAMILIES = (
    "node_kubelet_pressure",
    "runai_scheduling_quota",
    "k8s_scheduling_error",
    "runai_control_plane_error",
    "k8s_control_plane_error",
    "workload_startup_error",
    "image_pull_error",
    # The ranked universe matches failure_modes.yaml — the ontology's families
    # are rankable categories, not just signature-promotion targets.
    "gpu_hardware_error",
    "network_fabric_error",
    "cluster_network_error",
    "k8s_storage_error",
    "storage_backend_error",
    "workload_runtime_error",
    "observability_accuracy",
    "platform_auth_error",
)

DEFAULT_FAMILY_RULES: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "node_kubelet_pressure": (
        "kubernetes",
        ("kubernetes", "prometheus"),
        (
            "diskpressure",
            "memorypressure",
            "pidpressure",
            "node pressure",
            "evict",
            "kubelet",
            "device plugin",
            "node condition",
        ),
    ),
    "runai_scheduling_quota": (
        "prometheus",
        ("prometheus", "kubernetes", "runai"),
        (
            "preempt",
            "reclaim",
            "pod group",
            "podgroup",
            "gang",
            "fairshare",
            "over-quota",
            "over quota",
            "requested gpus",
            "quota",
            "idleness",
        ),
    ),
    "k8s_scheduling_error": (
        "kubernetes",
        ("kubernetes", "prometheus"),
        (
            "failedscheduling",
            "unschedulable",
            "untolerated taint",
            "node affinity/selector",
            "topology spread",
            "anti-affinity",
            "exceeded quota",
            "default-scheduler",
            "0/",
        ),
    ),
    "runai_control_plane_error": (
        "loki",
        ("loki", "kubernetes"),
        (
            "reconcile",
            "runai-backend",
            "cluster-sync",
            "authorization",
            "database error",
        ),
    ),
    "k8s_control_plane_error": (
        "kubernetes",
        ("kubernetes", "loki"),
        (
            "apiserver",
            "kube-apiserver",
            "etcd",
            "etcdserver",
            "kube-controller-manager",
            "kubeadm",
            "leaderelection",
            "failed calling webhook",
            "admission webhook",
        ),
    ),
    "workload_startup_error": (
        "kubernetes",
        ("kubernetes", "loki"),
        (
            "crashloopbackoff",
            "oomkilled",
            "failedmount",
            "createcontainer",
            "back-off restarting",
            "startup probe",
            "runcontainererror",
            "importerror",
            "permission denied",
        ),
    ),
    "image_pull_error": (
        "kubernetes",
        ("kubernetes", "loki"),
        (
            "imagepullbackoff",
            "errimagepull",
            "errimageneverpull",
            "manifest for",
            "toomanyrequests",
            "pull access denied",
            "no such host",
            "registry",
        ),
    ),
    "gpu_hardware_error": (
        "system",
        ("system", "loki", "kubernetes"),
        (
            "xid",
            "nvrm",
            "fallen off the bus",
            'no runtime for "nvidia"',
            "xidcriticalerror",
            "inforom",
            "nouveau",
            "gpu is lost",
        ),
    ),
    "network_fabric_error": (
        "loki",
        ("loki", "system"),
        (
            "nccl",
            "infiniband",
            "rdma",
            "nvlink",
            "nicclusterpolicy",
            "fabric manager",
            "gpudirect",
            "link flap",
        ),
    ),
    "cluster_network_error": (
        "kubernetes",
        ("kubernetes", "loki"),
        (
            "coredns",
            "cni plugin",
            "name resolution failed",
            "networkplugin",
            "no route to host",
        ),
    ),
    "k8s_storage_error": (
        "kubernetes",
        ("kubernetes", "loki"),
        (
            "failedmount",
            "failedattachvolume",
            "provisioningfailed",
            "volumebinding",
            "storageclass",
            "persistentvolumeclaim",
        ),
    ),
    "storage_backend_error": (
        "system",
        ("system", "loki", "kubernetes"),
        (
            "stale file handle",
            "read-only file system",
            "nfs server",
            "ceph",
            "input/output error",
        ),
    ),
    "workload_runtime_error": (
        "loki",
        ("loki", "kubernetes"),
        (
            "cuda out of memory",
            "torch.cuda",
            "traceback (most recent call last)",
            "segmentation fault",
            "core dumped",
        ),
    ),
    "observability_accuracy": (
        "prometheus",
        ("prometheus", "kubernetes"),
        (
            "dcgm-exporter",
            "metrics-exporter",
            "thanos",
            "missingruleevaluations",
            "rule evaluation",
        ),
    ),
    "platform_auth_error": (
        "loki",
        ("loki", "kubernetes", "runai"),
        (
            "saml",
            "oidc",
            "keycloak",
            "login failed",
            "invalid_grant",
            "access rule",
        ),
    ),
}

DEFAULT_FAMILY_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "node_kubelet_pressure",
        ("diskpressure", "memorypressure", "pidpressure", "kubelet", "node", "evict"),
    ),
    (
        "runai_scheduling_quota",
        ("quota", "queue", "preempt", "reclaim", "fairshare", "gang", "over-quota"),
    ),
    (
        "k8s_scheduling_error",
        ("failedscheduling", "unschedul", "taint", "affinity", "topology"),
    ),
    (
        "runai_control_plane_error",
        ("reconcile", "runai-backend", "cluster-sync", "authorization"),
    ),
    (
        "k8s_control_plane_error",
        ("apiserver", "etcd", "kubeadm", "leaderelection", "webhook", "kube-controller"),
    ),
    (
        "workload_startup_error",
        ("crashloop", "oom", "createcontainer", "startup probe", "runcontainer"),
    ),
    (
        "image_pull_error",
        ("imagepull", "errimagepull", "image", "registry", "manifest"),
    ),
    (
        "gpu_hardware_error",
        ("xid", "nvidia", "gpu", "dcgm"),
    ),
    (
        "network_fabric_error",
        ("nccl", "infiniband", "rdma", "nvlink", "fabric"),
    ),
    (
        "cluster_network_error",
        ("dns", "coredns", "cni", "network"),
    ),
    (
        "k8s_storage_error",
        ("volume", "pvc", "storageclass", "mount"),
    ),
    (
        "storage_backend_error",
        ("nfs", "ceph", "read-only"),
    ),
    (
        "workload_runtime_error",
        ("cuda", "runtime", "application"),
    ),
    (
        "observability_accuracy",
        ("metrics", "dcgm", "thanos", "prometheus"),
    ),
    (
        "platform_auth_error",
        ("auth", "login", "sso", "saml", "oidc", "permission"),
    ),
)

DEFAULT_FAMILY_REASONS = {
    "node_kubelet_pressure": "alert points at node/kubelet resource pressure",
    "runai_scheduling_quota": "alert points at Run:ai scheduling / GPU quota (preempt/reclaim)",
    "k8s_scheduling_error": "alert points at kube-scheduler placement (taint/affinity/quota)",
    "runai_control_plane_error": "alert implicates the Run:ai platform control plane",
    "k8s_control_plane_error": "alert implicates the Kubernetes cluster control plane",
    "workload_startup_error": "alert points at a workload-local startup/config/crash fault",
    "image_pull_error": "alert points at an image pull / registry failure",
    "gpu_hardware_error": "alert points at a GPU hardware/driver fault (NVIDIA XID)",
    "network_fabric_error": (
        "alert points at the GPU interconnect / multi-node fabric (NCCL/IB/NVLink)"
    ),
    "cluster_network_error": "alert points at cluster networking (CNI/DNS/pod network)",
    "k8s_storage_error": "alert points at the Kubernetes storage layer (CSI/PVC/StorageClass)",
    "storage_backend_error": "alert points at the backing storage system (NFS/Ceph/filesystem)",
    "workload_runtime_error": "alert points at the workload's own code failing at runtime",
    "observability_accuracy": (
        "alert points at the metrics/observability pipeline, not the workload"
    ),
    "platform_auth_error": "alert points at login/SSO/permissions (auth control plane)",
}


def default_family_catalog() -> FamilyCatalog:
    return FamilyCatalog(
        families=DEFAULT_FAMILIES,
        rules=dict(DEFAULT_FAMILY_RULES),
        hints=DEFAULT_FAMILY_HINTS,
        reasons=dict(DEFAULT_FAMILY_REASONS),
    )


def family_catalog_from_entries(raw: object) -> FamilyCatalog | None:
    entries = raw.get("families") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        return None

    families: list[str] = []
    rules: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {}
    hints: list[tuple[str, tuple[str, ...]]] = []
    reasons: dict[str, str] = {}
    seen: set[str] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            return None
        family = str(entry.get("family") or "").strip()
        if not family or family in seen:
            return None
        canonical = str(entry.get("canonical_agent") or "").strip()
        agents = _string_tuple(entry.get("agents"))
        keywords = _string_tuple(entry.get("keywords"), lower=True)
        planner_keywords = _string_tuple(
            entry.get("planner_keywords") or entry.get("keywords"),
            lower=True,
        )
        reason = str(entry.get("reason") or "").strip()
        if not (canonical and agents and keywords and planner_keywords and reason):
            return None
        seen.add(family)
        families.append(family)
        rules[family] = (canonical, agents, keywords)
        hints.append((family, planner_keywords))
        reasons[family] = reason

    if not families:
        return None
    return FamilyCatalog(tuple(families), rules, tuple(hints), reasons)


def load_family_catalog(path: str) -> FamilyCatalog:
    if not path:
        return default_family_catalog()
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError):
        return default_family_catalog()
    return family_catalog_from_entries(raw) or default_family_catalog()


def _string_tuple(value: object, *, lower: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    strings: list[str] = []
    for item in value:
        text = str(item).strip()
        if not text:
            continue
        strings.append(text.lower() if lower else text)
    return tuple(strings)


def load_troubleshooting_cases(path: str, *, max_chars: int = 12000) -> str:
    if not path:
        return ""
    try:
        content = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if len(content) <= max_chars:
        return content
    return content[:max_chars].rstrip() + "\n\n[truncated]"


def _normalize_alert_key(name: str) -> str:
    return "".join(ch for ch in (name or "").lower() if ch.isalnum())


def load_runai_alerts(path: str) -> dict[str, dict[str, Any]]:
    """Parse runai_alerts_catalog.yaml into {normalized_alert_name: entry}.

    Each entry: {alert, severity, category, family, trigger, actions[]}. Lets the
    RCA recognise a documented Run:ai built-in alert by name and immediately know
    what it means and how to fix it — no TypeDB required.
    """
    if not path:
        return {}
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("alert") or "").strip()
        if not name:
            continue
        out[_normalize_alert_key(name)] = {
            "alert": name,
            "severity": str(entry.get("severity") or ""),
            "category": str(entry.get("category") or ""),
            "family": str(entry.get("family") or ""),
            "trigger": str(entry.get("trigger") or ""),
            "actions": [str(a) for a in (entry.get("actions") or [])],
        }
    return out


def match_runai_alert(catalog: dict[str, dict[str, Any]], alert_name: str) -> dict[str, Any] | None:
    """Best-effort match of an incoming alert_name against the built-in catalog.

    Exact normalized match first, then substring either direction (handles the
    Prometheus CamelCase alertname vs the doc's spaced title). Guarded on length so
    short names can't false-match.
    """
    key = _normalize_alert_key(alert_name)
    if not key or not catalog:
        return None
    if key in catalog:
        return catalog[key]
    # Substring either direction (Prometheus CamelCase vs the doc's spaced title),
    # guarded on length. If a name is a common prefix of several entries (e.g.
    # "...Container Memory Usage" -> Critical AND Warning) the match is ambiguous,
    # so return None rather than guess a sibling.
    hits = [
        entry
        for cat_key, entry in catalog.items()
        if min(len(key), len(cat_key)) >= 15 and (key in cat_key or cat_key in key)
    ]
    return hits[0] if len(hits) == 1 else None


def load_architecture(path: str) -> dict[str, dict[str, Any]]:
    """Parse runai_architecture.yaml into {component_name: entry}.

    The platform topology layer (curated from the Run:ai architecture diagrams,
    names calibrated against a live cluster): per-component purpose, failure
    effect, dependency edges, control-plane DB schema ownership, and ready-to-run
    checks. Consumed by the playbook (check paths for `component:`-tagged
    symptoms) and the postgres drill-down (schema ownership hints)."""
    if not path:
        return {}
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("component") or "").strip()
        if not name:
            continue
        out[name] = {
            "component": name,
            "layer": str(entry.get("layer") or ""),
            "namespace": str(entry.get("namespace") or ""),
            "kind": str(entry.get("kind") or ""),
            "purpose": str(entry.get("purpose") or ""),
            "failure_effect": str(entry.get("failure_effect") or ""),
            "family": str(entry.get("family") or ""),
            "owns_schema": str(entry.get("owns_schema") or ""),
            "depends_on": [str(d) for d in (entry.get("depends_on") or [])],
            "checks": [str(c) for c in (entry.get("checks") or [])],
            "saas_only": bool(entry.get("saas_only")),
        }
    return out


def component_for_target(
    components: dict[str, dict[str, Any]], *names: str
) -> dict[str, Any] | None:
    """The platform component the alert TARGET itself is, by pod/workload name.

    The identity entry point into the topology knowledge: an alert ON
    runai-container-toolkit-vttmr implicates the runai-container-toolkit
    component (and its depends_on chain — the NVIDIA GPU Operator stack) even
    when every collector comes back empty, so no error-string signature is
    needed to reach the right playbook. Token-boundary match, longest component
    name wins (runai-backend-workloads over runai-backend)."""
    best: dict[str, Any] | None = None
    best_len = 0
    for raw in names:
        stem = str(raw or "").strip().lower()
        if not stem:
            continue
        padded = f"-{stem}-"
        for name, entry in components.items():
            token = f"-{name.lower()}-"
            if token in padded and len(name) > best_len:
                best = entry
                best_len = len(name)
    return best


def component_action_lines(components: dict[str, dict[str, Any]], name: str) -> list[str]:
    """Flat action strings for an implicated component — the identity-entry
    version of component_check_lines, shaped for the numbered actions list."""
    entry = components.get(name)
    if not entry:
        return []
    lines: list[str] = []
    effect = entry.get("failure_effect") or entry.get("purpose")
    if effect:
        lines.append(f"({name}) {effect}")
    chain = dependency_path(components, name)
    if len(chain) > 1:
        lines.append(f"Check order for {name}: " + " → ".join(chain))
    lines.extend(str(check) for check in (entry.get("checks") or [])[:3])
    return lines


def dependency_path(
    components: dict[str, dict[str, Any]], name: str, *, max_depth: int = 4
) -> list[str]:
    """BFS over depends_on from `name` — the order to check when `name` is
    implicated ("X is broken" -> also check what X needs). SaaS-only and unknown
    dependencies are skipped; the small static graph makes this a few hops."""
    start = components.get(name)
    if start is None:
        return []
    path, seen = [name], {name}
    frontier = list(start.get("depends_on") or [])
    for _ in range(max_depth):
        if not frontier:
            break
        next_frontier: list[str] = []
        for dep in frontier:
            if dep in seen:
                continue
            seen.add(dep)
            entry = components.get(dep)
            if entry is None or entry.get("saas_only"):
                continue
            path.append(dep)
            next_frontier.extend(entry.get("depends_on") or [])
        frontier = next_frontier
    return path


def component_check_lines(components: dict[str, dict[str, Any]], name: str) -> list[str]:
    """Playbook sub-lines for an implicated platform component: what it does,
    the dependency check order, and its ready-to-run checks."""
    entry = components.get(name)
    if not entry:
        return []
    lines: list[str] = []
    effect = entry.get("failure_effect") or entry.get("purpose")
    if effect:
        lines.append(f"  - Component `{name}`: {effect}")
    chain = dependency_path(components, name)
    if len(chain) > 1:
        lines.append("  - Check order: " + " → ".join(chain))
    lines.extend(f"  - `{check}`" for check in (entry.get("checks") or [])[:3])
    return lines


def load_failure_modes(path: str) -> dict[str, list[dict[str, Any]]]:
    """Parse failure_modes.yaml into {family: [{symptom, keywords[], actions[]}]}.

    Same shape the TypeDB knowledge layer returns, so the synthesis can render
    root-cause-relevant remediation locally without a live knowledge graph.
    """
    if not path:
        return {}
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError):
        return {}
    knowledge: dict[str, list[dict[str, Any]]] = {}
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        family = str(entry.get("family") or "").strip()
        if not family:
            continue
        for symptom in entry.get("symptoms") or []:
            if not isinstance(symptom, dict):
                continue
            knowledge.setdefault(family, []).append(
                {
                    "symptom": symptom.get("name") or "",
                    "keywords": [str(k).lower() for k in symptom.get("keywords") or []],
                    "actions": list(symptom.get("actions") or []),
                    # Optional link into runai_architecture.yaml: which platform
                    # component this symptom implicates (drives check paths).
                    "component": str(symptom.get("component") or ""),
                }
            )
    return knowledge


def load_runai_known_issues(path: str) -> list[dict[str, Any]]:
    """Parse runai_known_issues.yaml into a list of known-issue entries.

    Each entry: {issue, family, keywords[], reason, affected_version,
    fixed_version, actions[]}. Recognised by their signature keywords appearing in
    the collected evidence — ranking-independent, like the built-in alert catalog
    is recognised by name, and needing no TypeDB.
    """
    if not path:
        return []
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("issue") or "").strip()
        keywords = [str(k).lower() for k in (entry.get("keywords") or []) if str(k).strip()]
        if not name or not keywords:
            continue
        out.append(
            {
                "issue": name,
                "family": str(entry.get("family") or ""),
                "keywords": keywords,
                "reason": str(entry.get("reason") or ""),
                "affected_version": str(entry.get("affected_version") or ""),
                "fixed_version": str(entry.get("fixed_version") or ""),
                "actions": [str(a) for a in (entry.get("actions") or [])],
            }
        )
    return out


def match_runai_known_issues(
    catalog: list[dict[str, Any]], observed_text: str, *, fuzzy_query: str = ""
) -> list[dict[str, Any]]:
    """Known-issue entries whose signature keyword appears in the evidence text.

    Substring match on the lowercased evidence, ranking-independent. Returns every
    match — one incident can hit more than one known issue. Known support cases
    stay exact-signature only: fuzzy recall here polluted reports with unrelated
    case notes that shared generic GPU/workload words.
    """
    text = (observed_text or "").lower()
    if not text or not catalog:
        return []
    hits = []
    for entry in catalog:
        matched, _negated = _keyword_hits(text, entry["keywords"])
        if matched:
            hits.append(entry)
    return hits


def match_failure_mode_symptoms(
    failure_modes: dict[str, list[dict[str, Any]]],
    observed_text: str,
    top_family: str = "",
    *,
    fuzzy_query: str = "",
) -> list[tuple[str, dict[str, Any]]]:
    """Every curated symptom, across ALL families, whose keyword hits the evidence.

    The ontology entry point is the fine-grained signature match — NOT the coarse
    family ranking. Matches are ordered top-ranked-family first (the ranker is a
    soft prior for ordering, no longer a gate), so a precise fix from any family
    still surfaces, including families the ranker cannot even nominate (e.g.
    gpu_hardware_error, which is not one of the four ranked families). Works on any
    {family: [{symptom, keywords[], actions[]}]} map — the curated failure modes or
    the TypeDB knowledge layer.
    """
    text = (observed_text or "").lower()
    if not text or not failure_modes:
        return []
    matched: list[tuple[str, dict[str, Any], list[str], int, int]] = []
    all_keywords: list[str] = []
    position = 0
    for family, symptoms in failure_modes.items():
        for symptom in symptoms or []:
            keywords = [str(kw).lower() for kw in symptom.get("keywords", [])]
            all_keywords.extend(keywords)
            hits, _negated = _keyword_hits(text, keywords)
            if hits and _symptom_context_supported(family, symptom, text):
                matched.append((family, symptom, hits, max(len(kw) for kw in hits), position))
            position += 1
    if not matched and fuzzy_query:
        # Recall fallback, same contract as the known-issue matcher: BM25+synonyms
        # over the curated names+keywords, only when substring found nothing, only
        # against the alert's own text (fuzzy_query — collector summaries carry the
        # pipeline's status boilerplate, which BM25 would false-match), and tagged
        # so downstream (and the verify pass) can tell fuzzy from exact.
        docs = [
            (
                (family, symptom),
                f"{symptom.get('symptom') or ''} "
                + " ".join(str(kw) for kw in symptom.get("keywords") or []),
            )
            for family, symptoms in failure_modes.items()
            for symptom in symptoms or []
        ]
        matched = [
            (family, {**symptom, "matched_via": "bm25"})
            for (family, symptom), _score in BM25Index(docs).search(
                _redact_negated_keywords(fuzzy_query.lower(), all_keywords), top_k=3
            )
        ]
        matched.sort(key=lambda fs: fs[0] != top_family)
        return matched
    # More matched keywords = more specific symptom. Use the ranked family only
    # after that, so a broad shared phrase ("no such host", "sandbox runtime")
    # cannot beat a richer operator signature.
    matched.sort(key=lambda fs: (-len(fs[2]), -fs[3], fs[0] != top_family, fs[4]))
    kept: list[tuple[str, dict[str, Any]]] = []
    kept_hits: list[list[str]] = []
    for family, symptom, hits, _length, _pos in matched:
        if any(_hits_subsumed_by(hits, stronger) for stronger in kept_hits):
            continue
        if len(hits) == 1 and any(
            len(stronger) > 1 and hits[0] in _GENERIC_CONTEXT_HITS
            for stronger in kept_hits
        ):
            continue
        kept.append((family, symptom))
        kept_hits.append(hits)
    return kept


_GENERIC_CONTEXT_HITS = {
    "failed to create pod sandbox",
    "no such host",
    "out of memory",
}


def _symptom_context_supported(family: str, symptom: dict[str, Any], text: str) -> bool:
    if family != "image_pull_error" or symptom.get("symptom") != "Registry TLS Certificate Error":
        return True
    return any(
        marker in text
        for marker in (
            "imagepullbackoff",
            "errimagepull",
            "image pull",
            "failed to pull image",
            "pulling image",
            "registry",
            "crictl pull",
        )
    )


def _hits_subsumed_by(hits: list[str], stronger_hits: list[str]) -> bool:
    if hits == stronger_hits:
        return False
    return all(
        any(hit == stronger or hit in stronger for stronger in stronger_hits) for hit in hits
    )


def _keyword_hits(text: str, keywords: list[str]) -> tuple[list[str], bool]:
    hits: list[str] = []
    negated = False
    negated_spans: list[tuple[int, int]] = []
    for keyword in sorted(keywords, key=len, reverse=True):
        start = 0
        while keyword:
            idx = text.find(keyword, start)
            if idx < 0:
                break
            end = idx + len(keyword)
            if any(span_start <= idx and end <= span_end for span_start, span_end in negated_spans):
                start = end
                continue
            if _keyword_negated(text, idx, end):
                negated = True
                negated_spans.append((idx, end))
                start = end
                continue
            hits.append(keyword)
            break
    return hits, negated


def _keyword_negated(text: str, start: int, end: int) -> bool:
    prefix = text[max(0, start - 128) : start]
    suffix = re.sub(r"[{}()[\]|~=,;:.\"']+", " ", text[end : end + 64])
    if _NON_EVIDENCE_PREFIX_RE.search(prefix) and not _CONTRAST_PREFIX_RE.search(prefix):
        return True
    absent_prefix = bool(re.search(r"\babsent\s*\(.{0,160}$", prefix))
    if absent_prefix and not _CONTRAST_PREFIX_RE.search(prefix):
        return True
    if _POSITIVE_SUFFIX_RE.match(suffix):
        return False
    prefix_negated = (
        bool(_NEGATED_PREFIX_RE.search(prefix))
        and not _CONTRAST_PREFIX_RE.search(prefix)
        and not _POSITIVE_PREFIX_RE.search(prefix)
    )
    return bool(prefix_negated or _NEGATED_SUFFIX_RE.match(suffix))


def _redact_negated_keywords(text: str, keywords: list[str]) -> str:
    chars = list(text)
    redacted: list[tuple[int, int]] = []
    for keyword in sorted(set(keywords), key=len, reverse=True):
        start = 0
        while keyword:
            idx = text.find(keyword, start)
            if idx < 0:
                break
            end = idx + len(keyword)
            if any(span_start <= idx and end <= span_end for span_start, span_end in redacted):
                start = end
                continue
            if _keyword_negated(text, idx, end):
                chars[idx:end] = " " * (end - idx)
                redacted.append((idx, end))
            start = end
    for match in _FUZZY_TOKEN_RE.finditer(text):
        idx, end = match.span()
        if any(span_start <= idx and end <= span_end for span_start, span_end in redacted):
            continue
        if _keyword_negated(text, idx, end):
            chars[idx:end] = " " * (end - idx)
            redacted.append((idx, end))
    return "".join(chars)
