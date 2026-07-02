"""Shared investigation-plan type.

The orchestrator builds an InvestigationPlan up front (from alert labels, vector
similarity, and the ontology) and hands it to each collector so they scope their
queries to what this specific alert needs — instead of every agent always
scraping the Run:ai control plane. Lives in its own module (no LLM/collector
imports) so collectors can import the type without a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvestigationPlan:
    # One-line framing of what the orchestrator thinks is worth investigating.
    focus: str = ""
    # Namespaces each collector should look at (target namespace first; Run:ai
    # control-plane namespaces are only added when check_control_plane is True).
    namespaces: list[str] = field(default_factory=list)
    node: str = ""
    workload: str = ""
    pod: str = ""
    # Whether the Run:ai control plane is actually relevant to this alert.
    check_control_plane: bool = False
    # Ordered candidate areas: [{"family": str, "reason": str}].
    hypotheses: list[dict[str, str]] = field(default_factory=list)
    # "targeted" when vector/ontology gave a >=0.8 match, else "breadth_first".
    strategy: str = "targeted"
    # True only when a similar incident / ontology fact cleared the 0.8 bar.
    used_similarity: bool = False
    used_ontology: bool = False
    # Operator-facing narrative of the plan / how to approach when nothing matched.
    narrative: str = ""
    # The matched Run:ai built-in alert definition (name/severity/trigger/actions),
    # when this alert is one of the documented built-in alerts. None otherwise.
    matched_alert: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "focus": self.focus,
            "namespaces": self.namespaces,
            "node": self.node,
            "workload": self.workload,
            "pod": self.pod,
            "check_control_plane": self.check_control_plane,
            "hypotheses": self.hypotheses,
            "strategy": self.strategy,
            "used_similarity": self.used_similarity,
            "used_ontology": self.used_ontology,
            "narrative": self.narrative,
            "matched_alert": self.matched_alert,
        }
