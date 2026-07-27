"""LLM refinement of operator-recorded remediation actions for learned knowledge.

An evaluation's effective_action is the operator's own words about ONE incident
("kubectl get secret nonexistent-secret -n default ..."). Promoted verbatim it
freezes instance identifiers into reusable knowledge. This pass rewrites each
action into an instance-free form while preserving the operator's intent; any
shape mismatch or LLM failure falls back to the original text — the reviewer
can still edit actions by hand before activation.
"""

from __future__ import annotations

import json
import logging

from app.config import Settings
from app.llm import complete_json, llm_configured

_log = logging.getLogger(__name__)

_SYSTEM = (
    "You rewrite operator-recorded remediation actions into reusable operational "
    "knowledge for a Kubernetes / Run:ai RCA system.\n"
    "Rules:\n"
    "- Keep each action in its original language (Korean stays Korean, English stays English).\n"
    "- Replace incident-specific identifiers (pod/namespace/node/workload names, secret or "
    "configmap names, IPs, image tags) with short generic placeholders in angle brackets, "
    "e.g. <namespace>, <secret-name>. The incident_context lists known identifiers.\n"
    "- Preserve the operator's intent exactly: never add tools, flags, or steps that are not "
    "stated or directly implied. A purely diagnostic step stays diagnostic.\n"
    "- Keep imperative phrasing; one sentence per action where possible.\n"
    'Return JSON: {"actions": ["..."]} with the SAME number of actions in the same order.'
)


async def refine_actions(
    settings: Settings,
    *,
    family: str,
    mechanism: str,
    actions: list[str],
    context: dict[str, str] | None = None,
) -> tuple[list[str], bool]:
    """Return (actions, refined). Falls back to the input on any failure."""
    cleaned = [str(action).strip() for action in actions if str(action).strip()]
    if not cleaned or not llm_configured(settings):
        return cleaned, False
    user = json.dumps(
        {
            "family": family,
            "mechanism": mechanism,
            "incident_context": {
                key: value for key, value in (context or {}).items() if str(value).strip()
            },
            "actions": cleaned,
        },
        ensure_ascii=False,
    )
    decision = await complete_json(settings, system=_SYSTEM, user=user)
    raw = decision.get("actions") if isinstance(decision, dict) else None
    if not isinstance(raw, list):
        _log.warning("knowledge action refinement returned no actions list; keeping originals")
        return cleaned, False
    refined = [" ".join(str(action).split()) for action in raw]
    if len(refined) != len(cleaned) or any(not action for action in refined):
        _log.warning("knowledge action refinement shape mismatch; keeping originals")
        return cleaned, False
    return refined, refined != cleaned
