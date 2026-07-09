from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.knowledge import _keyword_hits

_MAX_DEPTH = 15


def load_tree(path: str | Path) -> dict[str, Any] | None:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, TypeError, yaml.YAMLError):
        return None
    if not isinstance(raw, dict):
        return None
    root = str(raw.get("root") or "").strip()
    raw_nodes = raw.get("nodes")
    if not root or not isinstance(raw_nodes, list):
        return None
    nodes: dict[str, dict[str, Any]] = {}
    for node in raw_nodes:
        if not isinstance(node, dict):
            return None
        node_id = str(node.get("id") or "").strip()
        if not node_id or not str(node.get("question") or "").strip():
            return None
        has_branches = isinstance(node.get("branches"), list)
        has_conclusion = isinstance(node.get("conclusion"), dict)
        if node.get("match") is None or has_branches == has_conclusion:
            return None
        nodes[node_id] = node
    if root not in nodes:
        return None
    return {"root": root, "nodes": nodes}


def walk_tree(tree: dict[str, Any] | None, evidence_text: str) -> dict[str, Any]:
    empty = {"path": [], "steps": [], "conclusion": None}
    try:
        if not isinstance(tree, dict):
            return empty
        nodes = tree.get("nodes")
        node_id = str(tree.get("root") or "").strip()
        if not node_id or not isinstance(nodes, dict):
            return empty
        text = str(evidence_text or "").lower()
        path: list[str] = []
        steps: list[dict[str, Any]] = []
        for _ in range(_MAX_DEPTH):
            node = nodes.get(node_id)
            if not isinstance(node, dict):
                break
            hits = _match_condition(node.get("match"), text)
            path.append(node_id)
            step = {
                "id": node_id,
                "question": str(node.get("question") or ""),
                "matched": hits,
            }
            steps.append(step)
            if not hits:
                break
            conclusion = node.get("conclusion")
            if isinstance(conclusion, dict):
                return {
                    "path": path,
                    "steps": steps,
                    "conclusion": {
                        "family": str(conclusion.get("family") or ""),
                        "summary": str(conclusion.get("summary") or ""),
                        "next_steps": [
                            str(item) for item in conclusion.get("next_steps") or []
                        ],
                    },
                }
            next_id = ""
            for branch in node.get("branches") or []:
                if not isinstance(branch, dict):
                    continue
                branch_hits = _match_condition(branch.get("match"), text)
                if branch_hits:
                    step["matched"] = branch_hits
                    next_id = str(branch.get("next") or "").strip()
                    break
            if not next_id or next_id not in nodes:
                break
            node_id = next_id
        return {"path": path, "steps": steps, "conclusion": None}
    except Exception:  # noqa: BLE001 - malformed trees must never break analysis
        return empty


def _match_condition(condition: object, text: str) -> list[str]:
    if not text:
        return []
    if isinstance(condition, str):
        return _hits(text, [condition])
    if isinstance(condition, list):
        return _hits(text, condition)
    if not isinstance(condition, dict):
        return []

    matched: list[str] = []
    for blocked in _hits(text, _strings(condition.get("not"))):
        if blocked:
            return []

    any_terms = _strings(condition.get("any") or condition.get("keywords"))
    fields = condition.get("fields")
    field_hits: list[str] = []
    if isinstance(fields, dict):
        field_required = not any_terms
        for field, values in fields.items():
            hits = _hits(text, _field_patterns(str(field), values))
            if not hits and field_required:
                return []
            field_hits.extend(hits)

    if any_terms:
        hits = _hits(text, any_terms)
        if not hits and not field_hits:
            return []
        matched.extend(hits)
        matched.extend(field_hits)
    elif field_hits:
        matched.extend(field_hits)

    all_terms = _strings(condition.get("all"))
    if all_terms:
        hits = _hits(text, all_terms)
        if len(set(hits)) < len(set(term.lower() for term in all_terms)):
            return []
        matched.extend(hits)

    return _dedupe(matched)


def _hits(text: str, terms: list[object]) -> list[str]:
    keywords = [str(term).strip().lower() for term in terms if str(term).strip()]
    if not keywords:
        return []
    return _keyword_hits(text, keywords)[0]


def _strings(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _field_patterns(field: str, values: object) -> list[str]:
    raw_field = field.strip().lower()
    if not raw_field:
        return []
    field_names = {
        raw_field,
        raw_field.replace("_", " "),
        raw_field.replace("_", "-"),
    }
    leaf = raw_field.rsplit("_", 1)[-1]
    if leaf in {"phase", "reason", "ready", "condition"}:
        field_names.add(leaf)
    patterns: list[str] = []
    for value in _strings(values):
        text = str(value).strip().lower()
        if not text:
            continue
        for name in field_names:
            patterns.extend((f"{name}: {text}", f"{name}={text}", f"{name} {text}"))
    return patterns


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
