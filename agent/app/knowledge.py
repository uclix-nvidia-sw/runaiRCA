from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


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
