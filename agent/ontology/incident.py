"""Standard Run:AI Incident record — the normalized form ingested into TypeDB.

One shape for the whole pipeline: ingestion writes it, the eval harness reads it.
Fields mirror what the backend already stores (incidents/alerts) plus the
operator-confirmed root cause, so ingestion is a deterministic projection of
existing data — no LLM extraction.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RootCause(BaseModel):
    category: str = ""        # validated against knowledge/families.yaml by ingest
    subtype: str = ""
    confidence: str = "low"   # low | medium | high
    blast_radius: str = ""    # node | queue | workload | ""
    statement: str = ""


class OntologyIncident(BaseModel):
    incident_id: str
    alert_id: str = ""
    correlation_key: str = ""
    analysis_summary: str = ""
    analysis_detail: str = ""
    run_id: str = ""
    analysis_hash: str = ""
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    harness: dict[str, Any] = Field(default_factory=dict)
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
    # Backend-persisted top root-cause family (empty for legacy rows).
    root_cause_family: str = ""
    # Explicit operator approval timestamp (dashboard Approve button); "" = not approved.
    user_approved_at: str = ""
    # Kept only to parse legacy fetch rows. Eligibility is user_approved_at.
    reviewed: bool = False
