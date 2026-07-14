from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from app.config import load_settings
from app.knowledge import (
    KnowledgeRegistry,
    load_family_catalog,
    load_runai_known_issues,
    set_runtime_knowledge_registry,
    validate_runtime_knowledge,
)
from app.schemas import (
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    ChatRequest,
    ChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
    RuntimeKnowledgeValidationResponse,
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
# The MCP SDK logs successful session negotiation and its optional standalone
# GET/SSE reconnect lifecycle at INFO for every short-lived tool session. An RCA
# can open hundreds of these sessions, drowning out actual analysis progress.
# Keep SDK warnings/errors; collector fallback warnings are emitted by app code.
logging.getLogger("mcp.client.streamable_http").setLevel(logging.WARNING)

settings = load_settings()
orchestrator = AnalysisOrchestrator(settings)
knowledge_registry = KnowledgeRegistry.from_settings(settings)
set_runtime_knowledge_registry(knowledge_registry)
family_catalog = load_family_catalog(settings.families_file)
evaluation_families = tuple(
    dict.fromkeys(
        (
            *family_catalog.families,
            *(
                str(issue.get("family") or "").strip()
                for issue in load_runai_known_issues(settings.runai_known_issues_file)
                if str(issue.get("family") or "").strip()
            ),
            "insufficient_evidence",
        )
    )
)

_MCP_SELF_CHECK_RETRY_DELAYS = (2.0, 5.0)


async def _log_mcp_reachability() -> None:
    """Best-effort MCP self-check that never gates Agent readiness."""
    try:
        from app.collectors.runai import _runai_headers
        from app.mcp_client import mcp_reachability

        urls = {
            "runai": settings.runai_mcp_url,
            "kubernetes": settings.kubernetes_mcp_url,
            "prometheus": settings.prometheus_mcp_url,
            "loki": settings.loki_mcp_url,
            "postgres": settings.postgres_mcp_url,
        }
        configured = {name for name, url in urls.items() if url}
        if not configured:
            return
        for attempt in range(len(_MCP_SELF_CHECK_RETRY_DELAYS) + 1):
            runai_headers: dict[str, str] = {}
            if settings.runai_mcp_url:
                runai_headers, _runai_auth_warnings = await _runai_headers(settings)
            report = await mcp_reachability(
                urls,
                headers_by_name={"runai": runai_headers},
            )
            if all(str(report.get(name, "")).startswith("ok (") for name in configured):
                return
            if attempt < len(_MCP_SELF_CHECK_RETRY_DELAYS):
                await asyncio.sleep(_MCP_SELF_CHECK_RETRY_DELAYS[attempt])
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - reachability report is best-effort
        logging.getLogger(__name__).debug("mcp reachability check failed", exc_info=True)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await knowledge_registry.start()
    if settings.enable_nat_runtime:
        try:
            await orchestrator.start_engine()
        except Exception:  # noqa: BLE001 - startup is best-effort
            logging.getLogger(__name__).exception("failed to start NAT engine")
    # A tools/list per configured service answers "are the agents actually on
    # MCP?" in pod logs. Run it after readiness is released and retry startup
    # races briefly: OAuth discovery or a restarting service must never hold the
    # Agent's lifespan startup.
    mcp_check = asyncio.create_task(_log_mcp_reachability())
    try:
        yield
    finally:
        mcp_check.cancel()
        with suppress(asyncio.CancelledError):
            await mcp_check
        await knowledge_registry.stop()
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
        "runtime_knowledge": knowledge_registry.health(),
    }


@app.post("/knowledge/validate", response_model=RuntimeKnowledgeValidationResponse)
def validate_knowledge(payload: dict[str, object]) -> dict[str, object]:
    """Internal, read-only contract check for compiled runtime knowledge."""
    return validate_runtime_knowledge(payload)


@app.get("/knowledge/families")
def root_cause_families() -> dict[str, list[str]]:
    """Return the finite family catalog that evaluation labels may use."""
    return {"families": list(evaluation_families)}


@app.post("/analyze", response_model=AlertAnalysisResponse)
async def analyze(request: AlertAnalysisRequest) -> AlertAnalysisResponse:
    return await orchestrator.analyze(request)


@app.post("/summarize-incident", response_model=IncidentSummaryResponse)
async def summarize_incident(request: IncidentSummaryRequest) -> IncidentSummaryResponse:
    return await orchestrator.summarize_incident(request)


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    return await orchestrator.chat(request)
