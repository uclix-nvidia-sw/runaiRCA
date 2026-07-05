from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.bm25 import BM25Index


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
    match — one incident can hit more than one known issue. When NO curated keyword
    hits and ``fuzzy_query`` is given (the ALERT's own text — never collector
    summaries, whose status boilerplate would false-match), a conservative
    BM25+synonym pass (app.bm25) recovers vocabulary drift; those entries are
    tagged ``matched_via: "bm25"`` and, like every match, still face the LLM
    verify pass downstream.
    """
    text = (observed_text or "").lower()
    if not text or not catalog:
        return []
    hits = [entry for entry in catalog if any(kw in text for kw in entry["keywords"])]
    if hits or not fuzzy_query:
        return hits
    # ponytail: index rebuilt per call — corpus is ~a dozen entries, <1ms; cache if profiled.
    index = BM25Index([(e, f"{e['issue']} {' '.join(e['keywords'])}") for e in catalog])
    return [
        {**entry, "matched_via": "bm25"} for entry, _score in index.search(fuzzy_query, top_k=2)
    ]


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
    matched: list[tuple[str, dict[str, Any]]] = []
    for family, symptoms in failure_modes.items():
        for symptom in symptoms or []:
            if any(str(kw).lower() in text for kw in symptom.get("keywords", [])):
                matched.append((family, symptom))
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
            for (family, symptom), _score in BM25Index(docs).search(fuzzy_query, top_k=3)
        ]
    # Stable sort: top-ranked family's matches first, otherwise file/query order
    # (which lists the more specific symptom before the generic one).
    matched.sort(key=lambda fs: fs[0] != top_family)
    return matched
