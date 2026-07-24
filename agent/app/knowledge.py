from __future__ import annotations

import asyncio
import copy
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx
import yaml

from app.bm25 import BM25Index

_log = logging.getLogger(__name__)

_FUZZY_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]{2,}")
_PROBE_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
# Alert-name concatenations (for example, KubePodImagePullBackOff) must retain
# suffix matching, so lexical boundary rules cannot distinguish same-suffix
# collisions. Extend this set only when a new collision is verified.
_ATOMIC_OBSERVATION_TOKENS = frozenset({"progressdeadlineexceeded"})
_STEM_SUFFIXES = frozenset({"e", "s", "es", "d", "ed", "ing", "ion", "ions", "er", "ers", "or", "ors"})
_BUNDLED_TROUBLESHOOTING_TREE = (
    Path(__file__).resolve().parent.parent / "knowledge" / "k8s_troubleshooting_tree.yaml"
)
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
    r"alert\s+label|schema\s+field|columns?|(?:later\s+)?dashboard\s+"
    r"(?:mentioned|showed|reported)|(?:historical|old|previous)\s+"
    r"(?:run|incident|log))\b|(?:환경변수|대시보드\s+필드)\b)"
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
    # Korean attributive/connective negation. A condition name commonly
    # appears before a parenthetical qualifier, e.g. ``MemoryPressure 등이
    # 아닌 순수 스케줄링 문제``. Treat these forms as local negation of the
    # preceding keyword, not as a positive condition assertion.
    r"|^\s*(?:\S+\s+){0,4}(?:은|는|이|가|도)?\s*"
    r"(?:아닌|아니라|아니며|아니고|아니지만|아니었|아니었던)\b"
    r"|^\s*(?:\S+\s+){0,4}(?:은|는|이|가|도)?\s*"
    r"(?:감지되지|발생하지|확인되지|관찰되지)\s*"
    r"(?:않(?:음|다|았|았음|았습니다|은|으며|고)|못(?:함|했다|했습니다))"
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
    # Nature axis: not a FAULT but a lifecycle event (rollout/upgrade in
    # progress). Cycling pods during a controller rollout or Helm upgrade are
    # expected disruption, not a hardware/node fault — this family names that so
    # an upgrade isn't mis-attributed to the incidental symptoms it produces.
    "platform_lifecycle_change",
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
            "evictionthresholdmet",
        ),
    ),
    "runai_scheduling_quota": (
        "prometheus",
        ("prometheus", "kubernetes", "runai"),
        (
            "preempt",
            "preemptlowerpriority",
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
            "nodes are available",
        ),
    ),
    "runai_control_plane_error": (
        "loki",
        ("loki", "kubernetes"),
        (
            "reconciler error",
            "runai-backend",
            "cluster-sync",
            "failed to reconcile",
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
            "failedmount",
            "createcontainererror",
            "createcontainerconfigerror",
            "backofflimitexceeded",
            "job has reached the specified backoff limit",
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
            "manifest unknown",
            "toomanyrequests",
            "pull access denied",
            "authentication required",
            "no basic auth credentials",
            "insufficient_scope",
            "repository does not exist",
            "name unknown",
            "dial tcp: lookup",
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
            "collective communicator",
            "remote transport",
            "completion queue",
            "retry exhaustion",
            "ncclinternalerror",
            "ncclsystemerror",
            "ncclunhandledcudaerror",
            "nccltimeout",
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
            "networkpluginnotready",
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
            "volume attach operation",
            "persistent claim",
            "device publication conflict",
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
            "cephfs",
            "input/output error",
        ),
    ),
    "workload_runtime_error": (
        "loki",
        ("loki", "kubernetes"),
        (
            "oomkilled",
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
    "platform_lifecycle_change": (
        "change",
        ("change",),
        (
            "mid-rollout",
            "observedgeneration",
            "rollingupdate",
            "pending-upgrade",
            "pending-install",
            "helm.sh/release",
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
    (
        "platform_lifecycle_change",
        ("rollout", "upgrade", "rollingupdate", "helm", "revision", "rolloutstuck"),
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
    "platform_lifecycle_change": (
        "alert coincides with a rollout/upgrade of the implicated component or its "
        "dependencies — expected disruption; verify the rollout/Helm release completed"
    ),
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


@dataclass(frozen=True)
class _ApprovedKnowledgeSnapshot:
    """Validated immutable-in-practice runtime payload ready for an atomic swap."""

    revision: str
    failure_modes: dict[str, tuple[dict[str, Any], ...]]
    active_failure_modes: dict[str, tuple[dict[str, Any], ...]]
    shadow_failure_modes: dict[str, tuple[dict[str, Any], ...]]
    known_issues: tuple[dict[str, Any], ...]
    active_known_issues: tuple[dict[str, Any], ...]
    shadow_known_issues: tuple[dict[str, Any], ...]
    probe_template_ids: dict[str, dict[str, tuple[str, ...]]]
    package_count: int
    active_package_ids: tuple[str, ...]
    shadow_package_ids: tuple[str, ...]


class KnowledgeRegistry:
    """Read-only runtime knowledge layered over version-controlled catalogs.

    The backend owns approval and exposes a GET-only snapshot endpoint.  A full
    payload is validated before replacing ``_snapshot``; callers therefore see
    either the last good revision or no runtime revision, never a partial one.
    """

    _MODES = {"off", "shadow", "assist", "authoritative"}

    def __init__(
        self,
        *,
        mode: str = "shadow",
        snapshot_url: str = "",
        token: str = "",
        refresh_seconds: int = 30,
        timeout_seconds: int = 10,
    ) -> None:
        self.mode = mode if mode in self._MODES else "shadow"
        self.snapshot_url = snapshot_url.rstrip("/")
        self._token = token
        self.refresh_seconds = max(30, refresh_seconds)
        self.timeout_seconds = max(1, timeout_seconds)
        self._snapshot: _ApprovedKnowledgeSnapshot | None = None
        self._etag = ""
        self._last_sync_at = ""
        self._last_sync_error = ""
        self._refresh_lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[None] | None = None

    @classmethod
    def from_settings(cls, settings: Any) -> KnowledgeRegistry:
        return cls(
            mode=str(getattr(settings, "dynamic_knowledge_mode", "shadow")),
            snapshot_url=str(getattr(settings, "runtime_knowledge_url", "")),
            token=str(getattr(settings, "runtime_knowledge_token", "")),
            refresh_seconds=int(getattr(settings, "runtime_knowledge_refresh_seconds", 30)),
            timeout_seconds=int(getattr(settings, "runtime_knowledge_timeout_seconds", 10)),
        )

    async def start(self) -> None:
        """Start the best-effort 30-second ETag refresh loop."""
        if self.mode == "off" or not self.snapshot_url:
            return
        await self.refresh()
        if self._refresh_task is None:
            self._refresh_task = asyncio.create_task(
                self._refresh_loop(), name="runtime-knowledge-refresh"
            )

    async def stop(self) -> None:
        task, self._refresh_task = self._refresh_task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self.refresh_seconds)
            await self.refresh()

    async def refresh(self) -> bool:
        """Fetch once, preserving the previous revision for every failed update."""
        if self.mode == "off" or not self.snapshot_url:
            return False
        async with self._refresh_lock:
            headers = {"Accept": "application/json"}
            if self._etag:
                headers["If-None-Match"] = self._etag
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.get(self.snapshot_url, headers=headers)
                if response.status_code == 304:
                    self._mark_sync_success()
                    return False
                response.raise_for_status()
                snapshot = _validate_approved_snapshot(response.json())
            except Exception as exc:  # noqa: BLE001 - a sync must never stop RCA
                self._last_sync_error = _sync_error(exc)
                _log.warning("runtime knowledge refresh failed: %s", self._last_sync_error)
                return False

            # This assignment is the sole mutation of the active runtime revision.
            # All validation above has completed, so readers cannot observe a
            # mixture of package revisions.
            self._snapshot = snapshot
            self._etag = response.headers.get("ETag", self._etag)
            self._mark_sync_success()
            return True

    def _mark_sync_success(self) -> None:
        self._last_sync_at = datetime.now(UTC).isoformat()
        self._last_sync_error = ""

    def health(self) -> dict[str, Any]:
        snapshot = self._snapshot
        return {
            "mode": self.mode,
            "configured": bool(self.snapshot_url),
            "loaded_revision": snapshot.revision if snapshot else None,
            "loaded_packages": snapshot.package_count if snapshot else 0,
            "active_package_ids": list(snapshot.active_package_ids) if snapshot else [],
            "shadow_package_ids": list(snapshot.shadow_package_ids) if snapshot else [],
            "probe_template_families": sorted(snapshot.probe_template_ids) if snapshot else [],
            "last_sync_at": self._last_sync_at or None,
            "last_sync_error": self._last_sync_error or None,
        }

    def failure_modes(
        self, baseline: dict[str, list[dict[str, Any]]]
    ) -> dict[str, list[dict[str, Any]]]:
        snapshot = self._snapshot
        if snapshot is None or self.mode not in {"assist", "authoritative"}:
            return copy.deepcopy(baseline)
        if self.mode == "assist":
            runtime = {
                family: list(symptoms)
                for family, symptoms in snapshot.active_failure_modes.items()
            }
            return _merge_failure_modes(baseline, runtime, authoritative=True)
        runtime = {family: list(symptoms) for family, symptoms in snapshot.failure_modes.items()}
        return _merge_failure_modes(baseline, runtime, authoritative=True)

    def known_issues(self, baseline: list[dict[str, Any]]) -> list[dict[str, Any]]:
        snapshot = self._snapshot
        if snapshot is None or self.mode not in {"assist", "authoritative"}:
            return copy.deepcopy(baseline)
        runtime = (
            snapshot.known_issues
            if self.mode == "authoritative"
            else snapshot.active_known_issues
        )
        return _merge_known_issues(baseline, list(runtime), authoritative=True)

    def shadow_hints(self, observed_text: str) -> list[tuple[str, dict[str, Any]]]:
        """Return evidence-matched shadow guidance without affecting matching."""
        snapshot = self._snapshot
        if self.mode != "assist" or snapshot is None:
            return []
        return match_failure_mode_symptoms(
            {
                family: list(symptoms)
                for family, symptoms in snapshot.shadow_failure_modes.items()
            },
            observed_text,
        )

    def provisional_catalogs(self) -> dict[str, Any]:
        """Return a copy of loaded runtime guidance without changing RCA ranking.

        Assist consumers such as a future UI card or probe adviser can use this
        method to inspect both active and shadow runtime guidance.
        """
        snapshot = self._snapshot
        if snapshot is None or self.mode == "off":
            return {
                "revision": None,
                "failure_modes": {},
                "known_issues": [],
                "probe_template_ids": {},
            }
        return {
            "revision": snapshot.revision,
            "failure_modes": {
                family: [copy.deepcopy(symptom) for symptom in symptoms]
                for family, symptoms in snapshot.failure_modes.items()
            },
            "known_issues": [copy.deepcopy(issue) for issue in snapshot.known_issues],
            "probe_template_ids": {
                family: {package_id: list(ids) for package_id, ids in packages.items()}
                for family, packages in snapshot.probe_template_ids.items()
            },
        }

    def probe_template_ids_for_family(
        self, family: str, *, include_assist: bool = True
    ) -> list[str]:
        """Return validated template IDs for safe planner/probe guidance only.

        Shadow never exposes runtime probes. Assist can expose their identifiers
        without changing RCA ranking; callers can disable that explicitly with
        ``include_assist=False``.
        """
        snapshot = self._snapshot
        if snapshot is None or self.mode not in {"assist", "authoritative"}:
            return []
        if self.mode == "assist" and not include_assist:
            return []
        values: list[str] = []
        for ids in snapshot.probe_template_ids.get(family, {}).values():
            for template_id in ids:
                if template_id not in values:
                    values.append(template_id)
        return values


_runtime_knowledge_registry: KnowledgeRegistry | None = None


def set_runtime_knowledge_registry(registry: KnowledgeRegistry | None) -> None:
    """Install the process registry used by the existing catalog load points."""
    global _runtime_knowledge_registry
    _runtime_knowledge_registry = registry


def validate_runtime_knowledge(payload: Any) -> dict[str, Any]:
    """Validate a read-only snapshot or one active/shadow compiled package.

    This is the canonical agent-side validator used by the internal HTTP route.
    It never writes a package or installs it in the live registry.
    """
    if not isinstance(payload, dict):
        return {"valid": False, "errors": ["payload must be a JSON object"], "normalized": None}
    snapshot_payload = payload
    if "packages" not in payload:
        snapshot_payload = {
            "revision": str(payload.get("revision") or "validation"),
            "packages": [payload],
        }
    try:
        snapshot = _validate_approved_snapshot(snapshot_payload)
    except (TypeError, ValueError) as exc:
        return {"valid": False, "errors": [str(exc)], "normalized": None}
    return {
        "valid": True,
        "errors": [],
        "normalized": _normalized_snapshot(snapshot),
    }


def _load_failure_modes(path: str) -> dict[str, list[dict[str, Any]]]:
    """Parse the version-controlled failure-mode knowledge into runtime entries.

    Same shape the TypeDB knowledge layer returns, so the synthesis can render
    root-cause-relevant remediation locally without a live knowledge graph. Optional
    localized labels/reasons/actions remain knowledge data rather than report-code
    conditionals.
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
                    "symptom_ko": symptom.get("name_ko") or "",
                    "keywords": [str(k).lower() for k in symptom.get("keywords") or []],
                    "actions": list(symptom.get("actions") or []),
                    "actions_ko": list(symptom.get("actions_ko") or []),
                    "reason": str(symptom.get("reason") or ""),
                    "reason_ko": str(symptom.get("reason_ko") or ""),
                    "exclusive_actions": bool(symptom.get("exclusive_actions", False)),
                    # Optional link into runai_architecture.yaml: which platform
                    # component this symptom implicates (drives check paths).
                    "component": str(symptom.get("component") or ""),
                }
            )
    return knowledge


def load_failure_modes(path: str) -> dict[str, list[dict[str, Any]]]:
    baseline = _load_failure_modes(path)
    registry = _runtime_knowledge_registry
    return registry.failure_modes(baseline) if registry else baseline


def merge_runtime_failure_modes(
    baseline: dict[str, list[dict[str, Any]]]
) -> dict[str, list[dict[str, Any]]]:
    registry = _runtime_knowledge_registry
    return registry.failure_modes(baseline) if registry else copy.deepcopy(baseline)


def runtime_shadow_hints(observed_text: str) -> list[tuple[str, dict[str, Any]]]:
    registry = _runtime_knowledge_registry
    return registry.shadow_hints(observed_text) if registry else []


def _load_runai_known_issues(path: str) -> list[dict[str, Any]]:
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


def load_runai_known_issues(path: str) -> list[dict[str, Any]]:
    baseline = _load_runai_known_issues(path)
    registry = _runtime_knowledge_registry
    return registry.known_issues(baseline) if registry else baseline


def _validate_approved_snapshot(payload: Any) -> _ApprovedKnowledgeSnapshot:
    """Validate the entire backend snapshot before it is eligible for a swap.

    Snapshot packages are intentionally read-only and already validated. Each
    package uses ``package_id``, ``state: active`` or ``state: shadow``, and a ``compiled`` object
    containing optional ``failure_modes`` / ``known_issues`` arrays. ``kind`` +
    ``entries`` is also accepted so a producer can send one knowledge type per
    package. Raw incident/case data is not a supported package shape.
    """
    if not isinstance(payload, dict):
        raise ValueError("snapshot must be a JSON object")
    revision = payload.get("revision")
    packages = payload.get("packages")
    if not isinstance(revision, str) or not revision.strip():
        raise ValueError("snapshot revision must be a non-empty string")
    if not isinstance(packages, list):
        raise ValueError("snapshot packages must be an array")

    failure_modes: dict[str, list[dict[str, Any]]] = {}
    active_failure_modes: dict[str, list[dict[str, Any]]] = {}
    shadow_failure_modes: dict[str, list[dict[str, Any]]] = {}
    known_issues: list[dict[str, Any]] = []
    active_known_issues: list[dict[str, Any]] = []
    shadow_known_issues: list[dict[str, Any]] = []
    probe_template_ids: dict[str, dict[str, tuple[str, ...]]] = {}
    active_package_ids: list[str] = []
    shadow_package_ids: list[str] = []
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise ValueError(f"package {index} must be an object")
        package_id = package.get("package_id", package.get("id"))
        if not isinstance(package_id, str) or not package_id.strip():
            raise ValueError(f"package {index} requires package_id")
        runtime_status = package.get(
            "runtime_status", package.get("state", package.get("status"))
        )
        if runtime_status not in {"active", "shadow"}:
            raise ValueError(f"package {package_id} has invalid runtime status")
        if runtime_status == "active":
            active_package_ids.append(package_id.strip())
        else:
            shadow_package_ids.append(package_id.strip())
        contents = package.get("compiled", package.get("knowledge", package.get("payload")))
        # The backend preserves package provenance in ``payload`` and places the
        # safe, compiled subset under payload.compiled. Never inspect the rest of
        # that payload (which may contain immutable case-snapshot metadata).
        if isinstance(contents, dict) and isinstance(contents.get("compiled"), dict):
            contents = contents["compiled"]
        if not isinstance(contents, dict):
            raise ValueError(f"package {package_id} compiled content must be an object")
        kind = str(package.get("kind") or "").strip().lower()
        entries = package.get("entries")
        if not kind and not (
            {"failure_modes", "known_issues", "probe_template_ids"} & contents.keys()
        ):
            raise ValueError(f"package {package_id} has no compiled knowledge")
        raw_failure_modes = contents.get("failure_modes", [])
        raw_known_issues = contents.get("known_issues", [])
        if kind in {"failure_mode", "failure_modes"}:
            raw_failure_modes = entries
        elif kind in {"known_issue", "known_issues"}:
            raw_known_issues = entries
        validated_modes = _validate_runtime_failure_modes(
            raw_failure_modes, package_id, runtime_status
        )
        for family, symptoms in validated_modes.items():
            failure_modes.setdefault(family, []).extend(symptoms)
            if runtime_status == "active":
                active_failure_modes.setdefault(family, []).extend(symptoms)
            else:
                shadow_failure_modes.setdefault(family, []).extend(symptoms)
        validated_issues = _validate_runtime_known_issues(
            raw_known_issues, package_id, runtime_status
        )
        known_issues.extend(validated_issues)
        if runtime_status == "active":
            active_known_issues.extend(validated_issues)
        else:
            shadow_known_issues.extend(validated_issues)
        for family, ids in _validate_runtime_probe_template_ids(
            contents.get("probe_template_ids"), package_id
        ).items():
            probe_template_ids.setdefault(family, {})[package_id.strip()] = ids

    return _ApprovedKnowledgeSnapshot(
        revision=revision.strip(),
        failure_modes={family: tuple(symptoms) for family, symptoms in failure_modes.items()},
        active_failure_modes={
            family: tuple(symptoms) for family, symptoms in active_failure_modes.items()
        },
        shadow_failure_modes={
            family: tuple(symptoms) for family, symptoms in shadow_failure_modes.items()
        },
        known_issues=tuple(known_issues),
        active_known_issues=tuple(active_known_issues),
        shadow_known_issues=tuple(shadow_known_issues),
        probe_template_ids=probe_template_ids,
        package_count=len(packages),
        active_package_ids=tuple(active_package_ids),
        shadow_package_ids=tuple(shadow_package_ids),
    )


def _normalized_snapshot(snapshot: _ApprovedKnowledgeSnapshot) -> dict[str, Any]:
    return {
        "revision": snapshot.revision,
        "active_package_ids": list(snapshot.active_package_ids),
        "failure_modes": {
            family: [copy.deepcopy(symptom) for symptom in symptoms]
            for family, symptoms in snapshot.failure_modes.items()
        },
        "known_issues": [copy.deepcopy(issue) for issue in snapshot.known_issues],
        "probe_template_ids": {
            family: {package_id: list(ids) for package_id, ids in packages.items()}
            for family, packages in snapshot.probe_template_ids.items()
        },
    }


@lru_cache(maxsize=1)
def _closed_family_set() -> frozenset[str]:
    import os

    return frozenset(
        load_family_catalog(os.getenv("FAMILIES_FILE", "knowledge/families.yaml")).families
    )


def _validate_runtime_failure_modes(
    value: Any, package_id: str, runtime_status: str
) -> dict[str, list[dict[str, Any]]]:
    if isinstance(value, dict):
        entries = [
            {"family": family, "symptoms": symptoms}
            for family, symptoms in value.items()
        ]
    elif isinstance(value, list):
        entries = value
    else:
        raise ValueError(f"package {package_id} failure_modes must be an array or object")
    out: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"package {package_id} has an invalid failure mode")
        family = entry.get("family")
        if not isinstance(family, str) or not family.strip():
            raise ValueError(f"package {package_id} failure mode requires family")
        # The family universe is closed (families.yaml == failure_modes ==
        # ranker vocabulary). A legacy or LLM-authored name must fail the
        # package here, not surface later as an ungroundable headline
        # (2026-07-24 audit, static defect 4).
        if family.strip() not in _closed_family_set():
            raise ValueError(
                f"package {package_id} failure mode family {family.strip()!r} "
                "is outside the closed catalog"
            )
        raw_symptoms = entry.get("symptoms")
        if raw_symptoms is None and "symptom" in entry:
            raw_symptoms = [entry]
        if not isinstance(raw_symptoms, list):
            raise ValueError(f"package {package_id} failure mode symptoms must be an array")
        for symptom in raw_symptoms:
            if not isinstance(symptom, dict):
                raise ValueError(f"package {package_id} has an invalid symptom")
            name = symptom.get("name", symptom.get("symptom"))
            keywords = symptom.get("keywords")
            actions = symptom.get("actions", [])
            actions_ko = symptom.get("actions_ko", [])
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"package {package_id} symptom requires name")
            if not isinstance(keywords, list) or not keywords or not all(
                isinstance(keyword, str) and keyword.strip() for keyword in keywords
            ):
                raise ValueError(f"package {package_id} symptom requires string keywords")
            if not isinstance(actions, list) or not all(
                isinstance(action, str) for action in actions
            ):
                raise ValueError(f"package {package_id} symptom actions must be strings")
            if not isinstance(actions_ko, list) or not all(
                isinstance(action, str) for action in actions_ko
            ):
                raise ValueError(f"package {package_id} symptom actions_ko must be strings")
            localized_text = {
                "symptom_ko": symptom.get("name_ko", symptom.get("symptom_ko", "")),
                "reason": symptom.get("reason", ""),
                "reason_ko": symptom.get("reason_ko", ""),
            }
            if any(not isinstance(text, str) for text in localized_text.values()):
                raise ValueError(f"package {package_id} symptom localized fields must be strings")
            exclusive_actions = symptom.get("exclusive_actions", False)
            if not isinstance(exclusive_actions, bool):
                raise ValueError(
                    f"package {package_id} symptom exclusive_actions must be a boolean"
                )
            component = symptom.get("component", "")
            if not isinstance(component, str):
                raise ValueError(f"package {package_id} symptom component must be a string")
            out.setdefault(family.strip(), []).append(
                {
                    "symptom": name.strip(),
                    "symptom_ko": localized_text["symptom_ko"].strip(),
                    "keywords": [keyword.strip().lower() for keyword in keywords],
                    "actions": list(actions),
                    "actions_ko": list(actions_ko),
                    "reason": localized_text["reason"].strip(),
                    "reason_ko": localized_text["reason_ko"].strip(),
                    "exclusive_actions": exclusive_actions,
                    "component": component,
                    "runtime_package_id": package_id,
                    "runtime_status": runtime_status,
                }
            )
    return out


def _validate_runtime_known_issues(
    value: Any, package_id: str, runtime_status: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"package {package_id} known_issues must be an array")
    out: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ValueError(f"package {package_id} has an invalid known issue")
        issue = entry.get("issue")
        keywords = entry.get("keywords")
        actions = entry.get("actions", [])
        if not isinstance(issue, str) or not issue.strip():
            raise ValueError(f"package {package_id} known issue requires issue")
        if not isinstance(keywords, list) or not keywords or not all(
            isinstance(keyword, str) and keyword.strip() for keyword in keywords
        ):
            raise ValueError(f"package {package_id} known issue requires string keywords")
        if not isinstance(actions, list) or not all(isinstance(action, str) for action in actions):
            raise ValueError(f"package {package_id} known issue actions must be strings")
        text_fields = ("family", "reason", "affected_version", "fixed_version")
        if any(not isinstance(entry.get(field, ""), str) for field in text_fields):
            raise ValueError(f"package {package_id} known issue fields must be strings")
        out.append(
            {
                "issue": issue.strip(),
                "family": entry.get("family", ""),
                "keywords": [keyword.strip().lower() for keyword in keywords],
                "reason": entry.get("reason", ""),
                "affected_version": entry.get("affected_version", ""),
                "fixed_version": entry.get("fixed_version", ""),
                "actions": list(actions),
                "runtime_package_id": package_id,
                "runtime_status": runtime_status,
            }
        )
    return out


def _validate_runtime_probe_template_ids(
    value: Any, package_id: str
) -> dict[str, tuple[str, ...]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"package {package_id} probe_template_ids must be an object")
    out: dict[str, tuple[str, ...]] = {}
    for family, raw_ids in value.items():
        if not isinstance(family, str) or not family.strip():
            raise ValueError(f"package {package_id} probe template family must be a string")
        if not isinstance(raw_ids, list) or not all(
            isinstance(template_id, str) and _PROBE_TEMPLATE_ID_RE.fullmatch(template_id)
            for template_id in raw_ids
        ):
            raise ValueError(
                f"package {package_id} probe template IDs must be safe identifier strings"
            )
        unknown_ids = [
            template_id
            for template_id in raw_ids
            if template_id not in _bundled_probe_template_ids()
        ]
        if unknown_ids:
            raise ValueError(
                f"package {package_id} references unknown bundled probe template IDs"
            )
        out[family.strip()] = tuple(dict.fromkeys(raw_ids))
    return out


@lru_cache(maxsize=1)
def _bundled_probe_template_ids() -> frozenset[str]:
    """Return only the existing bundled tree's stable probe-template IDs.

    A missing or malformed catalog fails closed: runtime packages may still
    carry failure-mode guidance, but no unverified probe ID can be activated.
    """
    try:
        raw = yaml.safe_load(_BUNDLED_TROUBLESHOOTING_TREE.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return frozenset()
    if not isinstance(raw, dict):
        return frozenset()
    ids: set[str] = set()
    for node in raw.get("nodes", []):
        if not isinstance(node, dict):
            continue
        for probe in node.get("probes", []):
            if not isinstance(probe, dict):
                continue
            template_id = probe.get("id")
            if isinstance(template_id, str) and _PROBE_TEMPLATE_ID_RE.fullmatch(template_id):
                ids.add(template_id)
    return frozenset(ids)


def _merge_failure_modes(
    baseline: dict[str, list[dict[str, Any]]],
    runtime: dict[str, list[dict[str, Any]]],
    *,
    authoritative: bool,
) -> dict[str, list[dict[str, Any]]]:
    merged = copy.deepcopy(baseline)
    for family, runtime_symptoms in runtime.items():
        current = merged.setdefault(family, [])
        existing = {
            str(symptom.get("symptom") or ""): index
            for index, symptom in enumerate(current)
        }
        for symptom in runtime_symptoms:
            identity = str(symptom.get("symptom") or "")
            if identity in existing:
                if authoritative:
                    current[existing[identity]] = copy.deepcopy(symptom)
                continue
            existing[identity] = len(current)
            current.append(copy.deepcopy(symptom))
    return merged


def _merge_known_issues(
    baseline: list[dict[str, Any]], runtime: list[dict[str, Any]], *, authoritative: bool
) -> list[dict[str, Any]]:
    merged = copy.deepcopy(baseline)
    existing = {str(issue.get("issue") or ""): index for index, issue in enumerate(merged)}
    for issue in runtime:
        identity = str(issue.get("issue") or "")
        if identity in existing:
            if authoritative:
                merged[existing[identity]] = copy.deepcopy(issue)
            continue
        existing[identity] = len(merged)
        merged.append(copy.deepcopy(issue))
    return merged


def _sync_error(exc: Exception) -> str:
    detail = str(exc).replace("\n", " ").strip()
    return f"{exc.__class__.__name__}: {detail[:240]}" if detail else exc.__class__.__name__


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
            hits.append({**entry, "matched_keywords": matched})
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
            (family, {**symptom, "matched_via": "bm25", "matched_keywords": []})
            for (family, symptom), _score in BM25Index(docs).search(
                _redact_negated_keywords(fuzzy_query.lower(), all_keywords), top_k=3
            )
        ]
        matched.sort(key=lambda fs: fs[0] != top_family)
        return matched
    # A generic state marker (ImagePullBackOff, CrashLoopBackOff, FailedMount)
    # names the retry/lifecycle state, not its mechanism. Any concrete error
    # signature must lead it even when the alert name contributes two generic
    # aliases (for example ImagePullBackOff + ErrImagePull versus one exact
    # ``dial tcp: lookup`` result). Within the same disposition, richer/longer
    # signatures still lead and the ranked family remains only a tie-breaker.
    matched.sort(
        key=lambda fs: (
            _only_generic_state_hits(fs[2]),
            -len(fs[2]),
            -fs[3],
            fs[0] != top_family,
            fs[4],
        )
    )
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
        kept.append((family, {**symptom, "matched_keywords": hits}))
        kept_hits.append(hits)
    return kept


_GENERIC_CONTEXT_HITS = {
    "failed to create pod sandbox",
    "no such host",
    "out of memory",
}

_GENERIC_STATE_HITS = frozenset(
    {
        "imagepullbackoff",
        "errimagepull",
        "crashloopbackoff",
        "failedscheduling",
        "unschedulable",
        "failedmount",
        "failedattachvolume",
    }
)


def _only_generic_state_hits(hits: list[str]) -> bool:
    return bool(hits) and all(hit in _GENERIC_STATE_HITS for hit in hits)


def _symptom_context_supported(family: str, symptom: dict[str, Any], text: str) -> bool:
    if family != "image_pull_error" or symptom.get("symptom") not in {
        "Registry Authentication Explicitly Rejected",
        "Image Repository Or Name Not Found",
        "Repository Existence Or Authorization Ambiguous",
        "Registry TLS Certificate Error",
        "Registry Server 5xx / DNS Lookup Failure On Pull",
    }:
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
            token_start = idx
            while token_start > 0 and text[token_start - 1].isascii() and text[
                token_start - 1
            ].isalnum():
                token_start -= 1
            token_end = end
            while token_end < len(text) and text[token_end].isascii() and text[
                token_end
            ].isalnum():
                token_end += 1
            token = text[token_start:token_end]
            if keyword[-1].isalnum() and end < len(text) and text[end].isascii() and text[end].isalnum():
                if text[end:token_end] not in _STEM_SUFFIXES:
                    start = end
                    continue
            # Guards the left-lenient suffix path for known compound tokens.
            if token != keyword and token in _ATOMIC_OBSERVATION_TOKENS:
                start = end
                continue
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
