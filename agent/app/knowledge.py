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
