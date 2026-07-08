"""Feedback-derived priors: turn operator up/down votes into per-family nudges.

Pure, deterministic, no LLM. `derive_priors` maps a list of feedback hints to a
`{family: multiplier}` dict consumed by `rank_root_cause_candidates(priors=...)`.
A multiplier <1.0 down-weights a family (operators disagreed with past RCAs that
blamed it); >1.0 up-weights it. Returns {} when no hint names a known family so
ranking is unchanged.

ponytail: substring keyword match, same vocabulary as root_cause_ranking. Two
context signals sharpen the flat accumulation (Tier 2):
  * relevance weight — each hint carries `weight` (memory hints set it to the
    source incident's similarity to the current alert), so a nudge from a highly
    similar incident counts more than one from a marginal match.
  * recency decay — hints carry `created_at`; older feedback is exponentially
    down-weighted (half-life `_HALF_LIFE_DAYS`) so stale opinions fade. Missing /
    unparseable timestamps decay to 1.0 (no change), preserving old behavior.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.knowledge import _keyword_hits

# Family -> phrases that, in feedback text, point at that family. Reuses the
# ranking vocabulary but tuned for human comments ("control plane", "GPU").
_FAMILY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "node_kubelet_pressure": (
        "node pressure", "kubelet", "disk pressure", "diskpressure",
        "memory pressure", "memorypressure", "eviction", "evict", "node",
    ),
    "runai_scheduling_quota": (
        "scheduling", "unschedulable", "quota", "preempt", "pending",
        "insufficient gpu", "gpu quota", "capacity", "saturat",
    ),
    "runai_control_plane_error": (
        "control plane", "control-plane", "reconcile", "admission",
        "runai-backend", "backend", "authorization", "database",
    ),
    "workload_startup_error": (
        "crashloop", "oomkill", "startup", "container", "mount",
    ),
    "image_pull_error": (
        "image pull", "imagepull", "errimagepull", "imagepullbackoff",
        "registry", "image", "manifest",
    ),
    "gpu_hardware_error": (
        "gpu hardware", "gpu error", "xid", "ecc", "nvlink", "hardware",
        "gpu fell off", "row remap", "gpu",
    ),
}

# Per-hint nudge applied per matched family, scaled by hint weight (default 1.0).
_STEP = 0.15
# Clamp so accumulated feedback can't zero out or wildly inflate a family.
_MIN, _MAX = 0.5, 1.5
# Recency decay: a hint this many days old contributes half as much. Feedback
# older than a few half-lives is effectively ignored.
_HALF_LIFE_DAYS = 30.0
# Floor so very old (but still relevant) feedback never fully vanishes.
_DECAY_FLOOR = 0.1


def derive_priors(feedback_hints: list, *, now: datetime | None = None) -> dict[str, float]:
    """Map operator feedback hints to per-family score multipliers.

    Down-votes / negative comments mentioning a family push its multiplier below
    1.0; up-votes / positive comments push it above. Each hint's nudge is scaled
    by its relevance `weight` and by a recency decay on `created_at`. `now` is
    injectable for deterministic tests; defaults to current UTC time.
    Deterministic given (`hints`, `now`), never raises.
    """
    ref = now or datetime.now(timezone.utc)
    deltas: dict[str, float] = {}
    for hint in feedback_hints or []:
        try:
            sentiment = (_attr(hint, "sentiment") or "").strip().lower()
            direction = _direction(sentiment)
            if direction == 0:
                continue
            weight = _weight(_attr(hint, "weight"))
            decay = _recency_decay(_attr(hint, "created_at"), ref)
            scaled = direction * _STEP * weight * decay
            if scaled == 0.0:
                continue
            text = (_attr(hint, "text") or "").lower()
            for family in _families_in(text, require_supported=direction > 0):
                deltas[family] = deltas.get(family, 0.0) + scaled
        except Exception:  # noqa: BLE001 — never raise into ranking
            continue

    return {
        fam: round(max(_MIN, min(_MAX, 1.0 + delta)), 3)
        for fam, delta in deltas.items()
        if delta != 0.0
    }


def _attr(hint: object, name: str) -> object:
    """Support pydantic models, dataclasses, and plain dicts."""
    if isinstance(hint, dict):
        return hint.get(name)
    return getattr(hint, name, None)


def _direction(sentiment: str) -> int:
    if sentiment in ("up", "positive", "+1", "thumbsup", "1"):
        return 1
    if sentiment in ("down", "negative", "-1", "thumbsdown"):
        return -1
    return 0


def _weight(raw: object) -> float:
    try:
        w = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 1.0
    # Ignore non-positive / absurd weights; keep influence bounded.
    if w <= 0:
        return 1.0
    return min(w, 3.0)


def _recency_decay(raw: object, ref: datetime) -> float:
    """Exponential age decay in [_DECAY_FLOOR, 1.0]; 1.0 when timestamp missing.

    A hint `_HALF_LIFE_DAYS` old contributes half as much. Future / unparseable
    timestamps decay to 1.0 so a bad clock never suppresses feedback.
    """
    when = _parse_ts(raw)
    if when is None:
        return 1.0
    age_days = (ref - when).total_seconds() / 86400.0
    if age_days <= 0:
        return 1.0
    return max(_DECAY_FLOOR, 0.5 ** (age_days / _HALF_LIFE_DAYS))


def _parse_ts(raw: object) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _families_in(text: str, *, require_supported: bool = False) -> set[str]:
    if not text:
        return set()
    hits_by_family = {
        fam: _keyword_hits(text, list(keywords))
        for fam, keywords in _FAMILY_KEYWORDS.items()
    }
    if require_supported:
        return {fam for fam, (hits, _negated) in hits_by_family.items() if hits}
    negated = {fam for fam, (_hits, was_negated) in hits_by_family.items() if was_negated}
    if negated:
        return negated
    return {fam for fam, (hits, _negated) in hits_by_family.items() if hits}
