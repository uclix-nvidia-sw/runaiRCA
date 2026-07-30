"""Turn curated guidance plus observed facts into an executable instruction.

Curated actions are written with placeholders (``kubectl describe pod <pod> -n
<ns>``) because they are family-level knowledge.  An operator reading a report
about ONE incident should not have to re-derive what ``<pod>`` was: this module
substitutes the values the run actually observed, and derives the one number the
catalogue cannot carry — how much memory to grant a container that was
OOMKilled at a known limit.

Only unambiguous placeholders are filled.  ``<name>`` means the PVC in one
curated line and a NetworkPolicy in the next, so it stays a placeholder: a
plausible-but-wrong command is worse than an honest blank.
"""

from __future__ import annotations

import difflib

# Binary suffixes first — "Mi" must win over the SI "M" prefix match.
_MEMORY_SUFFIXES: tuple[tuple[str, int], ...] = (
    ("Ki", 1024),
    ("Mi", 1024**2),
    ("Gi", 1024**3),
    ("Ti", 1024**4),
    ("k", 1000),
    ("K", 1000),
    ("M", 1000**2),
    ("G", 1000**3),
    ("T", 1000**4),
)

# Placeholder -> fact key. Every entry names exactly one thing in every curated
# line that uses it; ambiguous tokens are deliberately absent.
_PLACEHOLDERS: dict[str, str] = {
    "<ns>": "namespace",
    "<namespace>": "namespace",
    "<workload-ns>": "namespace",
    "<project-ns>": "namespace",
    "<pod>": "pod",
    "<node>": "node",
    "<image:tag>": "image",
    "<image>": "image",
    "<repo>": "repo",
    "<workload>": "workload",
}

# ponytail: a short list of images common enough that a near-miss is almost
# certainly a typo. Extend it when a real report misses one — it only ever adds
# a "check the spelling" hint, never a fix.
_WELL_KNOWN_REPOS = frozenset(
    {
        "nginx",
        "redis",
        "postgres",
        "mysql",
        "mariadb",
        "mongo",
        "busybox",
        "alpine",
        "ubuntu",
        "debian",
        "python",
        "node",
        "golang",
        "httpd",
        "memcached",
        "rabbitmq",
        "grafana/grafana",
        "prom/prometheus",
        "pytorch/pytorch",
        "tensorflow/tensorflow",
        "nvidia/cuda",
    }
)


def parse_memory(value: object) -> int | None:
    """Kubernetes memory quantity -> bytes. ``None`` when it is not parseable."""
    text = str(value or "").strip()
    if not text:
        return None
    for suffix, multiplier in _MEMORY_SUFFIXES:
        if text.endswith(suffix):
            try:
                return int(float(text[: -len(suffix)]) * multiplier)
            except ValueError:
                return None
    try:
        # Plain bytes, or the exponent form Kubernetes also accepts ("512e6").
        return int(float(text))
    except ValueError:
        return None


def format_memory(size: int) -> str:
    """Bytes -> the shortest exact Kubernetes quantity, else the next whole Mi."""
    for unit, multiplier in (("Gi", 1024**3), ("Mi", 1024**2), ("Ki", 1024)):
        if size >= multiplier and size % multiplier == 0:
            return f"{size // multiplier}{unit}"
    return f"{-(-size // 1024**2)}Mi"


def fill_placeholders(text: str, facts: dict[str, str]) -> str:
    """Substitute observed values for the unambiguous curated placeholders."""
    for token, key in _PLACEHOLDERS.items():
        value = str(facts.get(key) or "").strip()
        if value:
            text = text.replace(token, value)
    return text


# `kubectl set resources` only understands the built-in controllers. A Run:ai or
# Grove workload Pod is owned by a CRD (TrainingWorkload, PodClique, RunaiJob),
# where the same command fails — those need the CR's own pod template edited.
_SET_RESOURCES_KINDS = frozenset(
    {
        "cronjob",
        "daemonset",
        "deployment",
        "job",
        "replicaset",
        "replicationcontroller",
        "statefulset",
    }
)


def _set_resources_command(facts: dict[str, str], limit: str, request: str) -> str:
    """The command when kubectl can do it; otherwise the field path to edit."""
    namespace = str(facts.get("namespace") or "").strip()
    kind = str(facts.get("workload_kind") or "").strip().lower()
    workload = str(facts.get("workload") or "").strip()
    container = str(facts.get("container") or "").strip()
    if kind and kind not in _SET_RESOURCES_KINDS:
        scope = f"{kind}/{workload}" if workload else kind
        target = f"-n {namespace} {scope}" if namespace else scope
        return f"kubectl edit {target}  # raise the memory on its pod template"
    scope = f"{kind}/{workload}" if kind and workload else "<kind>/<workload>"
    parts = ["kubectl"]
    if namespace:
        parts.append(f"-n {namespace}")
    parts.append(f"set resources {scope}")
    if container:
        parts.append(f"-c {container}")
    parts.append(f"--limits=memory={limit} --requests=memory={request}")
    return " ".join(parts)


def memory_sizing_action(facts: dict[str, str], language: str) -> str:
    """Concrete limit/request values for a container OOMKilled at a known limit.

    The working set at kill time IS the limit, so the real requirement is only
    known to be *above* the current ceiling: the old limit becomes the new
    reservation and twice the old limit buys room to measure the true peak.
    Sizing is impossible without a configured limit, and a missing limit means
    node-level pressure, which the curated catalogue handles separately.
    """
    current_limit = parse_memory(facts.get("memory_limit"))
    if not facts.get("oom") or not current_limit:
        return ""
    limit_text = str(facts.get("memory_limit"))
    new_limit = format_memory(current_limit * 2)
    new_request = format_memory(current_limit)
    request_text = str(facts.get("memory_request") or "")
    container = str(facts.get("container") or "").strip()
    command = _set_resources_command(facts, new_limit, new_request)
    # A container whose request already equals its limit needs no request change;
    # "400Mi → 400Mi" reads like an instruction and is none.
    request_unchanged = parse_memory(request_text) == current_limit
    if language == "ko":
        target = f"컨테이너 `{container}`의 " if container else ""
        request_clause = (
            f"`resources.requests.memory`는 {new_request} 유지"
            if request_unchanged
            else "`resources.requests.memory` "
            + (f"{request_text} → " if request_text else "미설정 → ")
            + f"{new_request}(OOM 시점에 실제로 사용한 양)"
        )
        current = (
            f"`resources.limits.memory` {limit_text} → {new_limit}(초과한 상한의 2배), "
            + request_clause
        )
        return (
            f"{target}메모리를 증설하세요: {current}. 실행: `{command}` "
            "(Run:ai 워크로드는 submit/CR spec의 메모리 값을 수정)."
        )
    target = f"container `{container}`" if container else "the container"
    request_clause = (
        f"`resources.requests.memory` stays at {new_request}"
        if request_unchanged
        else "`resources.requests.memory` "
        + (f"{request_text} → " if request_text else "unset → ")
        + f"{new_request} (what it actually used when it was killed)"
    )
    current = (
        f"`resources.limits.memory` {limit_text} → {new_limit} (2x the ceiling it hit) and "
        + request_clause
    )
    return (
        f"Raise memory for {target}: {current}. Run: `{command}` "
        "(for a Run:ai workload, change the memory values in its submit/CR spec instead)."
    )


def image_typo_hint(facts: dict[str, str], language: str) -> str:
    """Flag an image repository that is one near-miss from a well-known name.

    Only reachable from an observed image-pull failure, so the reference is
    already known to be unpullable; this narrows "check the reference" to "check
    this spelling" for the common case.
    """
    repo = str(facts.get("repo") or "").strip()
    if not repo:
        return ""
    # Compare both the bare name ("ngink") and the org form ("prom/prometheu"),
    # dropping the registry host that carries no spelling signal.
    candidates = [repo.rsplit("/", 1)[-1]]
    if repo.count("/") >= 1:
        candidates.append("/".join(repo.split("/")[-2:]))
    for candidate in candidates:
        suspects = difflib.get_close_matches(
            candidate, sorted(_WELL_KNOWN_REPOS - {candidate}), n=1, cutoff=0.8
        )
        if not suspects:
            continue
        if language == "ko":
            return (
                f"이미지 repository `{candidate}`가 널리 쓰이는 `{suspects[0]}`와 거의 같습니다 — "
                "오타인지 먼저 확인하세요."
            )
        return (
            f"Image repository `{candidate}` is a near-match for the well-known "
            f"`{suspects[0]}` — check the spelling before anything else."
        )
    return ""


def image_repository(image: str) -> str:
    """Repository part of an image reference, without tag or digest."""
    reference = str(image or "").strip()
    if not reference:
        return ""
    reference = reference.split("@", 1)[0]
    # A colon before the last slash is a registry port, not a tag.
    head, separator, tail = reference.rpartition(":")
    if separator and "/" not in tail:
        reference = head
    return reference
