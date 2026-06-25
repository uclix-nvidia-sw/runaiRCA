from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Alert(BaseModel):
    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str | None = None
    endsAt: str | None = None
    generatorURL: str | None = None
    fingerprint: str = ""


class PreviousAnalysisContext(BaseModel):
    status: str
    summary: str
    detail: str
    created_at: str | None = None


class AlertAnalysisRequest(BaseModel):
    alert: Alert
    thread_ts: str = ""
    incident_id: str | None = None
    analysis_type: str | None = None
    previous_analysis: PreviousAnalysisContext | None = None
    language: str | None = None


class AlertAnalysisArtifact(BaseModel):
    agent: str
    source: str
    type: str
    status: str = "ok"
    confidence: str = "low"
    query: str | None = None
    result: dict[str, Any] | list[Any] | str | None = None
    summary: str | None = None


class AlertAnalysisResponse(BaseModel):
    status: str
    thread_ts: str
    analysis: str
    analysis_summary: str
    analysis_detail: str
    analysis_type: str
    analysis_quality: str
    missing_data: list[str]
    warnings: list[str]
    capabilities: dict[str, str]
    context: dict[str, Any]
    artifacts: list[AlertAnalysisArtifact]


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
    context: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


class ChatResponse(BaseModel):
    status: str
    answer: str
    conversation_id: str
