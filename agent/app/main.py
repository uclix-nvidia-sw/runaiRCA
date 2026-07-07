from __future__ import annotations

import logging
from contextlib import asynccontextmanager

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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if settings.enable_nat_runtime:
        try:
            await orchestrator.start_engine()
        except Exception:  # noqa: BLE001 - startup is best-effort
            logging.getLogger(__name__).exception("failed to start NAT engine")
    try:
        yield
    finally:
        await orchestrator.close_engine()


app = FastAPI(
    title="Run:AI RCA Agent",
    description="NeMo Agent Toolkit backed multi-agent RCA service",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "runai-rca-agent", "status": "ok"}


@app.get("/ping")
def ping() -> str:
    return "pong"


@app.get("/healthz")
def healthz() -> dict[str, object]:
    return {
        "status": "ok",
        "nemo_runtime": "enabled" if settings.enable_nat_runtime else "fallback",
        "nemo_engine": orchestrator.engine_health(),
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
