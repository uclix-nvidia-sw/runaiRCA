from __future__ import annotations

from app.bm25 import BM25Index, tokenize
from app.knowledge import (
    load_failure_modes,
    load_runai_known_issues,
    match_failure_mode_symptoms,
    match_runai_known_issues,
)

FAILURE_MODES = "knowledge/failure_modes.yaml"
KNOWN_ISSUES = "knowledge/runai_known_issues.yaml"


def test_tokenize_drops_stopwords_and_noise() -> None:
    assert tokenize("The pod is OOMKilled!") == ["pod", "oomkilled"]
    assert tokenize("") == []


def test_single_generic_shared_token_is_never_a_match() -> None:
    # "workload" appears in both docs (df/N too high for the signature rule and
    # only one query token hits) — one common word must not produce a match.
    index = BM25Index(
        [
            ("a", "workload crashloopbackoff restart"),
            ("b", "workload disk pressure kubelet"),
            ("c", "gang podgroup scheduling"),
        ]
    )
    assert index.search("some unrelated workload text") == []


def test_synonyms_bridge_vocabulary() -> None:
    # "evicted" reaches the preemption doc through the domain synonym group,
    # and the matched terms are signature-grade (df=1, long) — single hit is enough.
    index = BM25Index(
        [
            ("preempt", "preempted higher priority preemption victim preemptor"),
            ("quota", "over quota contention overquota exceeded"),
            ("image", "imagepullbackoff registry manifest"),
            ("probe", "startup probe failed unhealthy"),
            ("nfs", "nfs server unresponsive stale mount"),
        ]
    )
    hits = index.search("the training job was evicted by the scheduler")
    assert [key for key, _ in hits] == ["preempt"]


def test_empty_index_and_empty_query() -> None:
    assert BM25Index([]).search("anything") == []
    assert BM25Index([("a", "text")]).search("") == []


def test_failure_mode_fuzzy_fallback_recovers_paraphrase() -> None:
    # No curated keyword substring-matches this alert text (no bare "evicted"
    # keyword; "preempted by higher priority" etc. all miss), so the substring
    # layer returns nothing — the synonym group (evicted→preempt/reclaim) must
    # surface the scheduling symptoms, tagged as fuzzy.
    fm = load_failure_modes(FAILURE_MODES)
    text = "workload evicted so another project could use the gpus"
    matches = match_failure_mode_symptoms(fm, text, "", fuzzy_query=text)
    assert matches, "fuzzy fallback found nothing"
    families = {family for family, _ in matches}
    assert "runai_scheduling_quota" in families
    assert all(sym.get("matched_via") == "bm25" for _, sym in matches)


def test_fuzzy_is_off_without_a_fuzzy_query() -> None:
    # Callers that don't pass the alert text keep the exact pre-BM25 behaviour —
    # collector summaries must never be fuzzy-matched (their status boilerplate,
    # e.g. "service account token is not available", false-matches symptoms).
    fm = load_failure_modes(FAILURE_MODES)
    text = "workload evicted so another project could use the gpus"
    assert match_failure_mode_symptoms(fm, text, "") == []


def test_exact_matches_keep_priority_and_are_untagged() -> None:
    # When a curated keyword hits, behaviour is byte-for-byte the old one:
    # substring matches only, no bm25 tag, no fuzzy additions.
    fm = load_failure_modes(FAILURE_MODES)
    matches = match_failure_mode_symptoms(
        fm, "pod stuck in crashloopbackoff", "", fuzzy_query="pod stuck in crashloopbackoff"
    )
    assert matches
    assert all("matched_via" not in sym for _, sym in matches)


def test_known_issue_fuzzy_fallback_is_conservative() -> None:
    catalog = load_runai_known_issues(KNOWN_ISSUES)
    # Benign text stays unmatched even through the fuzzy path (same contract as
    # test_no_false_match)...
    benign = "a perfectly healthy cluster log line"
    assert match_runai_known_issues(catalog, benign, fuzzy_query=benign) == []
    # ...and an exact signature still returns the untagged exact entry.
    exact = "Error: the administrator prohibited modifying item 'project-data'"
    hits = match_runai_known_issues(catalog, exact, fuzzy_query=exact)
    assert hits and all("matched_via" not in h for h in hits)
