"""Tiny BM25 index with Run:ai-domain synonym expansion. Stdlib only.

Recall layer for the signature matchers in app.knowledge (idea borrowed from
the former API-spec search): the curated substring keywords stay
the precision entry point, and BM25 runs only when they matched NOTHING, so
existing behaviour never changes. It bridges vocabulary drift the substring
layer cannot ("job was preempted" vs the curated "preempted by higher
priority"), and the LLM verify pass downstream still gets to refute fuzzy
matches like any other candidate.

Conservative by design — a document qualifies only when
  - at least two distinct query tokens hit it and one hit term is corpus-rare
    (df/N <= 0.25), OR
  - a single query token hits a signature-grade term (df <= 2, df/N <= 0.25,
    len >= 6), e.g. "preempted"
so one shared generic word ("workload", "node") can never produce a match.
"""

from __future__ import annotations

import math
import re
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9]+")

_STOPWORDS = frozenset(
    "a an and are as at be been by for from had has have in is it its no not "
    "of on or that the this to was were will with".split()
)

# Domain synonym groups: each token also matches the others in its group.
# Small and curated like the keyword lists themselves — extend as gaps show up.
_SYNONYM_GROUPS: tuple[tuple[str, ...], ...] = (
    (
        "preempt",
        "preempted",
        "preemption",
        "preemptor",
        "evict",
        "evicted",
        "eviction",
        "reclaim",
        "reclaimed",
        "reclaiming",
    ),
    ("oom", "oomkill", "oomkilled"),
    ("quota", "overquota"),
    ("gpu", "cuda", "nvidia"),
    ("crash", "crashed"),
    ("crashloop", "crashloopbackoff"),
    ("imagepullbackoff", "errimagepull", "errimageneverpull"),
    ("pending", "unschedulable", "unscheduled"),
    ("namespace", "ns", "project"),
    ("delete", "deleted", "remove", "removed"),
    ("disk", "filesystem"),
    ("volume", "pvc"),
    ("permission", "denied", "forbidden", "unauthorized", "rbac"),
)

_SYNONYMS: dict[str, frozenset[str]] = {}
for _group in _SYNONYM_GROUPS:
    for _term in _group:
        _SYNONYMS[_term] = frozenset(t for t in _group if t != _term)

# Qualification gates (see module docstring).
_RARE_DF_RATIO = 0.25
_SIGNATURE_DF = 2
_SIGNATURE_LEN = 6
_NON_EVIDENCE_TERMS = frozenset(
    {
        "application",
        "app",
        "alert",
        "auth",
        "bound",
        "cache",
        "cached",
        "catalog",
        "caught",
        "capacity",
        "completed",
        "config",
        "container",
        "count",
        "coredns",
        "cuda",
        "current",
        "dashboard",
        "delete",
        "deleted",
        "defined",
        "docs",
        "documentation",
        "enabled",
        "entry",
        "error",
        "errors",
        "event",
        "exception",
        "exceeded",
        "enough",
        "example",
        "expression",
        "failed",
        "failure",
        "field",
        "filesystem",
        "free",
        "job",
        "key",
        "kubelet",
        "label",
        "legend",
        "limit",
        "lines",
        "logs",
        "manager",
        "metric",
        "mounted",
        "name",
        "gpu",
        "healthy",
        "image",
        "memory",
        "network",
        "namespace",
        "nvidia",
        "normal",
        "normally",
        "node",
        "pod",
        "present",
        "placeholder",
        "payload",
        "prometheus",
        "quota",
        "query",
        "reason",
        "recording",
        "remove",
        "removed",
        "reachable",
        "ready",
        "running",
        "rule",
        "rules",
        "sample",
        "schema",
        "scheduler",
        "series",
        "state",
        "succeeded",
        "succeeding",
        "stayed",
        "storage",
        "startup",
        "stable",
        "threshold",
        "unknown",
        "workload",
        "zero",
    }
)


def tokenize(text: str) -> list[str]:
    """Lowercased alphanumeric tokens, minus stopwords and 1-char noise."""
    return [
        t for t in _TOKEN_RE.findall((text or "").lower()) if len(t) > 1 and t not in _STOPWORDS
    ]


class BM25Index:
    """BM25 over a tiny curated corpus (tens to hundreds of short docs).

    ``docs`` is ``[(key, text), ...]``; ``search`` returns ``[(key, score),
    ...]`` best-first. Keys are carried through untouched, so callers can use
    whole entries as keys.
    """

    def __init__(self, docs: list[tuple[Any, str]], *, k1: float = 1.5, b: float = 0.75):
        self._k1 = k1
        self._b = b
        self._keys = [key for key, _ in docs]
        self._tf: list[dict[str, int]] = []
        self._lengths: list[int] = []
        self._df: dict[str, int] = {}
        for _, text in docs:
            counts: dict[str, int] = {}
            tokens = tokenize(text)
            for tok in tokens:
                counts[tok] = counts.get(tok, 0) + 1
            self._tf.append(counts)
            self._lengths.append(len(tokens))
            for tok in counts:
                self._df[tok] = self._df.get(tok, 0) + 1
        self._n = len(docs)
        self._avgdl = (sum(self._lengths) / self._n) if self._n else 0.0

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        return math.log(1 + (self._n - df + 0.5) / (df + 0.5))

    def search(self, query: str, *, top_k: int = 3) -> list[tuple[Any, float]]:
        """Qualified candidates for ``query`` (any length of evidence text)."""
        if not self._n:
            return []
        query_tokens = list(dict.fromkeys(tokenize(query)))
        if not query_tokens:
            return []
        scores = [0.0] * self._n
        hit_sources: list[set[str]] = [set() for _ in range(self._n)]
        rare_hit = [False] * self._n
        signature_hit = [False] * self._n
        for source in query_tokens:
            for term in (source, *_SYNONYMS.get(source, ())):
                df = self._df.get(term)
                if not df:
                    continue
                idf = self._idf(term)
                rare = df / self._n <= _RARE_DF_RATIO
                evidence = source not in _NON_EVIDENCE_TERMS and term not in _NON_EVIDENCE_TERMS
                signature = rare and df <= _SIGNATURE_DF and len(term) >= _SIGNATURE_LEN
                for i, counts in enumerate(self._tf):
                    tf = counts.get(term)
                    if not tf:
                        continue
                    denom = tf + self._k1 * (
                        1 - self._b + self._b * self._lengths[i] / (self._avgdl or 1.0)
                    )
                    scores[i] += idf * tf * (self._k1 + 1) / denom
                    if evidence:
                        hit_sources[i].add(source)
                        rare_hit[i] = rare_hit[i] or rare
                        signature_hit[i] = signature_hit[i] or signature
        qualified = [
            (self._keys[i], scores[i])
            for i in range(self._n)
            if scores[i] > 0.0
            and (
                (len(hit_sources[i]) >= 2 and rare_hit[i])
                or (len(hit_sources[i]) == 1 and signature_hit[i])
            )
        ]
        qualified.sort(key=lambda ks: -ks[1])
        return qualified[:top_k]
