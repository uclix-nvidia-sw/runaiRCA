from __future__ import annotations

import logging

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


class _HealthzFilter(logging.Filter):
    """Drop kubelet probe noise (/healthz, /ping) from the uvicorn access log.

    The probes are liveness/readiness checks from the node, not AI/agent traffic —
    they drowned out the useful investigation logs. The endpoints themselves stay."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return "/healthz" not in msg and "/ping" not in msg


logging.getLogger("uvicorn.access").addFilter(_HealthzFilter())
# The RCA investigation narrates plan/collect/synthesis at INFO so the pod log
# shows what the agents are doing instead of probe noise.
logging.basicConfig(level=logging.INFO)

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
