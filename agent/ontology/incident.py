"""Standard Run:AI Incident record — the normalized form ingested into TypeDB.

One shape for the whole pipeline: ingestion writes it, the eval harness reads it.
Fields mirror what the backend already stores (incidents/alerts) plus the
operator-confirmed root cause, so ingestion is a deterministic projection of
existing data — no LLM extraction.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# Allowed root-cause families — must match schema.tql sub-types and
# app/services/root_cause_ranking.py.
FAMILIES = (
    "node_kubelet_pressure",
    "scheduling_quota_exhaustion",
    "control_plane_error",
    "workload_startup_image_failure",
    "insufficient_evidence",
)


class RootCause(BaseModel):
    category: str = ""        # one of FAMILIES
    subtype: str = ""
    confidence: str = "low"   # low | medium | high
    blast_radius: str = ""    # node | queue | workload | ""
    statement: str = ""


class OntologyIncident(BaseModel):
    incident_id: str
    alert_id: str = ""
    correlation_key: str = ""
    analysis_summary: str = ""
    title: str = ""
    severity: str = "warning"
    status: str = "firing"
    fired_at: str = ""
    cluster: str = ""
    node: str = ""
    namespace: str = ""
    project: str = ""
    queue: str = ""
    workload_name: str = ""
    workload_type: str = ""
    alert_name: str = ""
    fingerprint: str = ""
    occurrence_count: int = 0
    occurrence_pods: list[str] = Field(default_factory=list)
    root_cause: RootCause | None = None
    # KB-poisoning guard (critique #1): only reviewed incidents are committed.
    reviewed: bool = False
