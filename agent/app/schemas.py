from __future__ import annotations

from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, Field


class Alert(BaseModel):
    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str | None = None
    endsAt: str | None = None
    generatorURL: str | None = None
    fingerprint: str = ""


class RuntimeKnowledgePackage(BaseModel):
    """Read-only approved knowledge package supplied by the backend snapshot API.

    This is deliberately a transport contract, not an authoring model.  A package
    must have completed approval and activation before it can reach an agent.
    """

    package_id: str
    state: Literal["active"] = Field(validation_alias=AliasChoices("state", "status"))
    compiled: dict[str, Any] = Field(
        validation_alias=AliasChoices("compiled", "knowledge", "payload")
    )


class RuntimeKnowledgeSnapshot(BaseModel):
    revision: str
    packages: list[RuntimeKnowledgePackage] = Field(default_factory=list)


class RuntimeKnowledgeValidationResponse(BaseModel):
    """Non-mutating result from the internal compiled-knowledge validator."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    normalized: dict[str, Any] | None = None


class PreviousAnalysisContext(BaseModel):
    status: str
    summary: str
    detail: str
    created_at: str | None = None


class SimilarIncidentContext(BaseModel):
    incident_id: str
    alert_id: str | None = None
    title: str = ""
    severity: str = ""
    status: str = ""
    similarity: float = 0
    analysis_summary: str = ""
    analysis_detail: str | None = None
    positive_feedback: int = 0
    negative_feedback: int = 0
    comment_count: int = 0
    root_cause_family: str = ""
    approved: bool = False


class FeedbackHintContext(BaseModel):
    source_id: str = ""
    sentiment: str = ""
    weight: float = 0
    text: str = ""
    created_at: str | None = None


class AlertAnalysisRequest(BaseModel):
    alert: Alert
    thread_ts: str = ""
    incident_id: str | None = None
    # Backend-supplied run identifier. When set, the /analyze task is registered
    # under it so POST /analyze/cancel can stop this specific run mid-flight.
    run_id: str = ""
    analysis_type: str | None = None
    seed_family: str = ""
    occurrence_count: int = 0
    occurrence_pods: list[str] = Field(default_factory=list)
    previous_analysis: PreviousAnalysisContext | None = None
    similar_incidents: list[SimilarIncidentContext] = Field(default_factory=list)
    feedback_hints: list[FeedbackHintContext] = Field(default_factory=list)
    language: str | None = None


class AlertAnalysisArtifact(BaseModel):
    # Stable within one analysis response (E01, E02, ...). The TypeDB ingest
    # qualifies this with run_id, so the same readable ID may safely recur later.
    evidence_id: str | None = None
    agent: str
    source: str
    type: str
    status: str = "ok"
    confidence: str = "low"
    query: str | None = None
    result: dict[str, Any] | list[Any] | str | None = None
    summary: str | None = None
    # Human-facing card title (e.g. "파드 조회") — the UI falls back to `type`.
    title: str | None = None
    # Problem signals extracted from `result` (base.salient_markers) — the UI
    # marks these in red inside the rendered evidence.
    highlights: list[str] | None = None


class AlertAnalysisResponse(BaseModel):
    status: str
    # Machine-readable terminal outcome for HTTP-200 responses that did not
    # produce an RCA. Backends must not treat these as successful analyses.
    terminal_reason: str | None = None
    thread_ts: str
    analysis: str
    analysis_summary: str
    analysis_detail: str
    analysis_type: str
    analysis_quality: str
    root_cause_family: str = ""
    missing_data: list[str]
    warnings: list[str]
    capabilities: dict[str, str]
    context: dict[str, Any]
    artifacts: list[AlertAnalysisArtifact]
    # Concrete pod names the agent actually discovered for the alert subject
    # (the real workload's pods), so the dashboard can show the impacted pods
    # instead of the kube-state-metrics EXPORTER pod named in the alert payload.
    affected_pods: list[str] = Field(default_factory=list)


class AlertSummaryInput(BaseModel):
    fingerprint: str
    alert_name: str
    severity: str
    status: str
    analysis_summary: str | None = None
    analysis_detail: str | None = None
    artifacts: list[AlertAnalysisArtifact] | None = None


class IncidentSummaryRequest(BaseModel):
    incident_id: str
    title: str
    severity: str
    fired_at: str
    resolved_at: str
    alerts: list[AlertSummaryInput]
    language: str | None = None


class IncidentSummaryResponse(BaseModel):
    status: str
    title: str
    summary: str
    detail: str


class ChatRequest(BaseModel):
    message: str
    conversation_id: str | None = None
    language: str | None = None
    page: str | None = None
    auto: bool = False
    incident_id: str | None = None
    alert_id: str | None = None
    incident_title: str | None = None
    incident_content: str | None = None
    alert_title: str | None = None
    alert_content: str | None = None
    context: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


class ChatResponse(BaseModel):
    status: str
    answer: str
    message: str | None = None
    response: str | None = None
    conversation_id: str
