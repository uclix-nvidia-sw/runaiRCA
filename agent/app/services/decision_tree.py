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
    return {
        "root": root,
        "nodes": nodes,
        "principles": [str(item) for item in raw.get("principles") or []],
        "sources": [str(item) for item in raw.get("sources") or []],
    }


def resolve_tree(
    graph_tree: object, failure_modes_path: str | Path
) -> tuple[dict[str, Any] | None, str]:
    """TypeDB is authoritative; the adjacent YAML is an availability fallback."""
    if isinstance(graph_tree, dict) and graph_tree.get("root") and graph_tree.get("nodes"):
        return graph_tree, "typedb"
    try:
        fallback = Path(failure_modes_path or "knowledge/failure_modes.yaml").with_name(
            "k8s_troubleshooting_tree.yaml"
        )
    except (TypeError, ValueError):
        fallback = Path("knowledge/k8s_troubleshooting_tree.yaml")
    return load_tree(fallback), "yaml-fallback"


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
            # The tree is curated operational knowledge, not just a classifier.
            # Keep the senior operator's check/decision with each matched branch so
            # synthesis can explain why it moved to the next branch.
            for key in ("verify", "interpretation", "avoid"):
                value = str(node.get(key) or "").strip()
                if value:
                    step[key] = value
            steps.append(step)
            if not hits:
                break
            conclusion = node.get("conclusion")
            if isinstance(conclusion, dict):
                result = {
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
                for key in ("confidence", "disconfirm"):
                    value = conclusion.get(key)
                    if value:
                        result["conclusion"][key] = value
                if tree.get("principles"):
                    result["principles"] = tree["principles"]
                if tree.get("sources"):
                    result["sources"] = tree["sources"]
                return result
            candidates: list[tuple[str, list[str]]] = []
            for branch in node.get("branches") or []:
                if not isinstance(branch, dict):
                    continue
                branch_hits = _match_condition(branch.get("match"), text)
                next_id = str(branch.get("next") or "").strip()
                if branch_hits and next_id in nodes:
                    candidates.append((next_id, branch_hits))
            specific = [candidate for candidate in candidates if candidate[1] != ["always"]]
            candidates = specific or candidates
            if not candidates:
                break
            next_id, branch_hits = candidates[0]
            step["matched"] = branch_hits
            alternatives = []
            for alternative_id, alternative_hits in candidates[1:]:
                alternative = nodes[alternative_id]
                conclusion = alternative.get("conclusion") or {}
                alternatives.append(
                    {
                        "id": alternative_id,
                        "question": str(alternative.get("question") or ""),
                        "matched": alternative_hits,
                        **(
                            {"family": str(conclusion.get("family") or "")}
                            if isinstance(conclusion, dict)
                            else {}
                        ),
                    }
                )
            if alternatives:
                step["alternatives"] = alternatives
            if not next_id or next_id not in nodes:
                break
            node_id = next_id
        return {"path": path, "steps": steps, "conclusion": None}
    except Exception:  # noqa: BLE001 - malformed trees must never break analysis
        return empty


def _match_condition(condition: object, text: str) -> list[str]:
    if isinstance(condition, dict) and condition.get("always") is True:
        return ["always"]
    if not text:
        return []
    if isinstance(condition, str):
        return _hits(text, [condition])
    if isinstance(condition, list):
        return _hits(text, condition)
    if not isinstance(condition, dict):
        return []

    # A root/fallback node may deliberately represent the universal first
    # triage step. This keeps an unfamiliar symptom visible as "need evidence"
    # instead of making the whole operational path disappear.
    matched: list[str] = []
    for blocked in _hits(text, _strings(condition.get("not"))):
        if blocked:
            return []

    any_terms = _strings(condition.get("any") or condition.get("keywords"))
    # Some Kubernetes event signatures contain words such as "no endpoints"
    # that are normally negation-filtered for RCA ranking. In a curated decision
    # branch, `literal_any` names the complete event signature and must win.
    literal_hits = _literal_hits(text, _strings(condition.get("literal_any")))
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
        if not hits and not literal_hits and not field_hits:
            return []
        matched.extend(hits)
        matched.extend(literal_hits)
        matched.extend(field_hits)
    elif literal_hits:
        matched.extend(literal_hits)
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


def _literal_hits(text: str, terms: list[object]) -> list[str]:
    hits: list[str] = []
    for term in terms:
        value = str(term).strip().lower()
        if value and value in text:
            hits.append(value)
    return hits


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
