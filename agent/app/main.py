from __future__ import annotations

from fastapi import FastAPI

from app.config import load_settings
from app.schemas import (
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    ChatRequest,
    ChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
)
from app.services.orchestrator import AnalysisOrchestrator

settings = load_settings()
orchestrator = AnalysisOrchestrator(settings)

app = FastAPI(
    title="Run:AI RCA Agent",
    description="NeMo Agent Toolkit backed multi-agent RCA service",
    version="0.1.0",
)


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "runai-rca-agent", "status": "ok"}


@app.get("/ping")
def ping() -> str:
    return "pong"


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {
        "status": "ok",
        "nemo_runtime": "enabled" if settings.enable_nat_runtime else "fallback",
    }


@app.post("/analyze", response_model=AlertAnalysisResponse)
async def analyze(request: AlertAnalysisRequest) -> AlertAnalysisResponse:
    return await orchestrator.analyze(request)


@app.post("/summarize-incident", response_model=IncidentSummaryResponse)
async def summarize_incident(request: IncidentSummaryRequest) -> IncidentSummaryResponse:
    return await orchestrator.summarize_incident(request)


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    return await orchestrator.chat(request)
