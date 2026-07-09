from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _nonnegative_int_env(name: str, default: int, invalid: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return invalid


def _csv_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv(name)
    if not raw:
        return default
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    return values or default


def _json_string_list_env(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be a JSON array of regex strings") from exc
    if not isinstance(parsed, list):
        raise ValueError(f"{name} must be a JSON array of regex strings")
    patterns: list[str] = []
    for idx, item in enumerate(parsed):
        if not isinstance(item, str):
            raise ValueError(f"{name}[{idx}] must be a regex string")
        pattern = item.strip()
        if not pattern:
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"{name}[{idx}] must be a valid regex") from exc
        patterns.append(pattern)
    return tuple(patterns)


@dataclass(frozen=True)
class Settings:
    port: int
    log_level: str
    language: str
    kubernetes_api_url: str
    kubernetes_token_path: str
    kubernetes_ca_path: str
    kubernetes_timeout_seconds: int
    kubernetes_list_limit: int
    kubernetes_namespaces: tuple[str, ...]
    kubernetes_cluster_scope_enabled: bool
    kubernetes_mcp_url: str
    runai_base_url: str
    runai_bearer_token: str
    runai_client_id: str
    runai_client_secret: str
    runai_token_url: str
    runai_workloads_path: str
    runai_projects_path: str
    runai_queues_path: str
    runai_version_path: str
    runai_timeout_seconds: int
    runai_mcp_url: str
    prometheus_url: str
    prometheus_timeout_seconds: int
    prometheus_mcp_url: str
    loki_url: str
    loki_bearer_token: str
    loki_basic_username: str
    loki_basic_password: str
    loki_tenant_id: str
    loki_timeout_seconds: int
    loki_query_limit: int
    loki_mcp_url: str
    runai_log_namespaces: tuple[str, ...]
    collectors: tuple[str, ...]
    backend_url: str
    postgres_dsn: str
    postgres_timeout_seconds: int
    runai_db_dsn: str
    postgres_mcp_url: str
    troubleshooting_cases_file: str
    architecture_file: str
    failure_modes_file: str
    families_file: str
    runai_alerts_file: str
    runai_known_issues_file: str
    enable_system_agent: bool
    system_agent_url: str
    system_agent_token: str
    system_agent_timeout_seconds: int
    enable_pod_exec: bool
    pod_exec_timeout_seconds: int
    agent_souls_file: str
    masking_regex_list: tuple[str, ...]
    builtin_redaction_enabled: bool
    builtin_redaction_hash_mode: bool
    llm_base_url: str
    llm_model: str
    llm_model_planner: str
    llm_model_investigation: str
    llm_model_drilldown: str
    llm_model_self_check: str
    llm_model_synthesis: str
    llm_model_chat: str
    llm_pricing_json: str
    llm_api_key: str
    llm_request_timeout_seconds: int
    nat_config_file: str
    enable_nat_runtime: bool
    typedb_address: str
    typedb_database: str
    typedb_username: str
    typedb_password: str
    typedb_tls_enabled: bool
    typedb_timeout_seconds: int
    enable_typedb: bool
    enable_investigation_loop: bool
    max_investigation_steps: int
    max_reanalysis_steps: int
    analysis_token_budget: int
    enable_agent_drilldown: bool
    drilldown_max_steps: int
    analysis_deadline_seconds: int
    # Defaulted (keeps existing Settings(...) constructions source-compatible).
    # Completion budget for the one-shot Korean report JSON: reasoning models
    # spend it on reasoning tokens FIRST — if synthesis logs empty replies
    # (finish_reason=length), raise this rather than shrinking the prompt.
    llm_synthesis_max_tokens: int = 8192
    llm_model_insight: str = ""
    max_investigation_iterations: int = 2


def load_settings() -> Settings:
    language = os.getenv("LANGUAGE", "en").strip().lower()
    if language not in {"en", "ko"}:
        language = "en"

    return Settings(
        port=_int_env("PORT", 8000),
        log_level=os.getenv("LOG_LEVEL", "info"),
        language=language,
        kubernetes_api_url=os.getenv("KUBERNETES_API_URL", "https://kubernetes.default.svc")
        .strip()
        .rstrip("/"),
        kubernetes_token_path=os.getenv(
            "KUBERNETES_TOKEN_PATH",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ).strip(),
        kubernetes_ca_path=os.getenv(
            "KUBERNETES_CA_PATH",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        ).strip(),
        # Collector ceilings are generous so agents gather DEEP evidence (thin
        # evidence came from cutting them off early); the overall analysis deadline
        # is the real bound. A single slow collector still fails gracefully.
        kubernetes_timeout_seconds=_int_env("KUBERNETES_TIMEOUT_SECONDS", 120),
        kubernetes_list_limit=max(1, _int_env("KUBERNETES_LIST_LIMIT", 50)),
        kubernetes_namespaces=_csv_env("KUBERNETES_NAMESPACES", ()),
        kubernetes_cluster_scope_enabled=_bool_env("KUBERNETES_CLUSTER_SCOPE_ENABLED", True),
        kubernetes_mcp_url=os.getenv("KUBERNETES_MCP_URL", "").strip().rstrip("/"),
        runai_base_url=os.getenv("RUNAI_BASE_URL", "").strip().rstrip("/"),
        runai_bearer_token=os.getenv("RUNAI_BEARER_TOKEN", "").strip(),
        runai_client_id=os.getenv("RUNAI_CLIENT_ID", "").strip(),
        runai_client_secret=os.getenv("RUNAI_CLIENT_SECRET", "").strip(),
        runai_token_url=os.getenv("RUNAI_TOKEN_URL", "").strip(),
        runai_workloads_path=os.getenv("RUNAI_WORKLOADS_PATH", "/api/v1/workloads").strip(),
        runai_projects_path=os.getenv("RUNAI_PROJECTS_PATH", "/api/v1/projects").strip(),
        runai_queues_path=os.getenv("RUNAI_QUEUES_PATH", "/api/v1/queues").strip(),
        # Run:ai control-plane version endpoint — enables version-aware suppression of
        # already-fixed known issues. Best-effort; override per your Run:ai API.
        runai_version_path=os.getenv("RUNAI_VERSION_PATH", "/api/v1/version").strip(),
        runai_timeout_seconds=_int_env("RUNAI_TIMEOUT_SECONDS", 120),
        runai_mcp_url=os.getenv("RUNAI_MCP_URL", "").strip().rstrip("/"),
        prometheus_url=os.getenv("PROMETHEUS_URL", "").strip().rstrip("/"),
        prometheus_timeout_seconds=_int_env("PROMETHEUS_TIMEOUT_SECONDS", 120),
        prometheus_mcp_url=os.getenv("PROMETHEUS_MCP_URL", "").strip().rstrip("/"),
        loki_url=os.getenv("LOKI_URL", "").strip().rstrip("/"),
        loki_bearer_token=os.getenv("LOKI_BEARER_TOKEN", "").strip(),
        loki_basic_username=os.getenv("LOKI_BASIC_USERNAME", "").strip(),
        loki_basic_password=os.getenv("LOKI_BASIC_PASSWORD", "").strip(),
        loki_tenant_id=os.getenv("LOKI_TENANT_ID", "").strip(),
        loki_timeout_seconds=_int_env("LOKI_TIMEOUT_SECONDS", 120),
        loki_query_limit=max(1, _int_env("LOKI_QUERY_LIMIT", 20)),
        loki_mcp_url=os.getenv("LOKI_MCP_URL", "").strip().rstrip("/"),
        runai_log_namespaces=_csv_env("RUNAI_LOG_NAMESPACES", ("runai", "runai-backend")),
        collectors=_csv_env(
            "COLLECTORS",
            ("runai", "kubernetes", "postgres", "prometheus", "loki", "system", "change"),
        ),
        backend_url=os.getenv("BACKEND_URL", "").strip().rstrip("/"),
        postgres_dsn=os.getenv("POSTGRES_DSN", "").strip(),
        postgres_timeout_seconds=_int_env("POSTGRES_TIMEOUT_SECONDS", 60),
        # Optional DSN for the Run:ai control-plane Postgres (the platform's own
        # DB: workloads/clusters/audit/... schemas). When set, the postgres
        # agent's drill-down can SELECT related platform data during
        # troubleshooting instead of only health-checking the RCA store. Use a
        # read-only DB role; the tool additionally enforces single-statement
        # SELECT inside a READ ONLY transaction.
        runai_db_dsn=os.getenv("RUNAI_DB_DSN", "").strip(),
        postgres_mcp_url=os.getenv("POSTGRES_MCP_URL", "").strip().rstrip("/"),
        troubleshooting_cases_file=os.getenv(
            "TROUBLESHOOTING_CASES_FILE",
            "knowledge/troubleshooting_cases.md",
        ).strip(),
        # Run:ai platform topology (components, depends_on, DB schema ownership)
        # — powers playbook check paths and the postgres drill-down schema hints.
        architecture_file=os.getenv(
            "ARCHITECTURE_FILE",
            "knowledge/runai_architecture.yaml",
        ).strip(),
        failure_modes_file=os.getenv(
            "FAILURE_MODES_FILE",
            "knowledge/failure_modes.yaml",
        ).strip(),
        families_file=os.getenv(
            "FAMILIES_FILE",
            "knowledge/families.yaml",
        ).strip(),
        runai_alerts_file=os.getenv(
            "RUNAI_ALERTS_FILE",
            "knowledge/runai_alerts_catalog.yaml",
        ).strip(),
        runai_known_issues_file=os.getenv(
            "RUNAI_KNOWN_ISSUES_FILE",
            "knowledge/runai_known_issues.yaml",
        ).strip(),
        # System agent (node infra: syslog/journalctl/dmesg via the per-node DaemonSet).
        # On by default; degrades to "unavailable" when SYSTEM_AGENT_URL isn't set.
        enable_system_agent=_bool_env("ENABLE_SYSTEM_AGENT", True),
        system_agent_url=os.getenv("SYSTEM_AGENT_URL", "").strip().rstrip("/"),
        system_agent_token=os.getenv("SYSTEM_AGENT_TOKEN", "").strip(),
        system_agent_timeout_seconds=_int_env("SYSTEM_AGENT_TIMEOUT_SECONDS", 120),
        # Read-only pod exec for the Kubernetes agent (view container state/logs; no mutations).
        enable_pod_exec=_bool_env("ENABLE_POD_EXEC", True),
        pod_exec_timeout_seconds=_int_env("POD_EXEC_TIMEOUT_SECONDS", 120),
        agent_souls_file=os.getenv("AGENT_SOULS_FILE", "prompts/agent_souls.md").strip(),
        masking_regex_list=_json_string_list_env("MASKING_REGEX_LIST_JSON"),
        builtin_redaction_enabled=_bool_env("BUILTIN_REDACTION_ENABLED", True),
        builtin_redaction_hash_mode=_bool_env("BUILTIN_REDACTION_HASH_MODE", False),
        llm_base_url=os.getenv("LLM_BASE_URL", "").strip().rstrip("/"),
        llm_model=os.getenv("LLM_MODEL", "").strip(),
        llm_model_planner=os.getenv("LLM_MODEL_PLANNER", "").strip(),
        llm_model_investigation=os.getenv("LLM_MODEL_INVESTIGATION", "").strip(),
        llm_model_drilldown=os.getenv("LLM_MODEL_DRILLDOWN", "").strip(),
        llm_model_self_check=os.getenv("LLM_MODEL_SELF_CHECK", "").strip(),
        llm_model_synthesis=os.getenv("LLM_MODEL_SYNTHESIS", "").strip(),
        llm_model_chat=os.getenv("LLM_MODEL_CHAT", "").strip(),
        llm_model_insight=os.getenv("LLM_MODEL_INSIGHT", "").strip(),
        llm_pricing_json=os.getenv("LLM_PRICING_JSON", "{}").strip(),
        llm_api_key=os.getenv("LLM_API_KEY", "").strip(),
        # Generous per-call ceiling so a reasoning agent is never cut off mid-thought;
        # the overall analysis deadline below is the real bound. (0 = unlimited.)
        llm_request_timeout_seconds=_int_env("LLM_REQUEST_TIMEOUT_SECONDS", 300),
        # Completion budget for the one-shot Korean report JSON. Reasoning models
        # spend this on reasoning tokens FIRST — if synthesis logs empty replies
        # (finish_reason=length), raise this rather than shrinking the prompt.
        llm_synthesis_max_tokens=_int_env("LLM_SYNTHESIS_MAX_TOKENS", 8192),
        nat_config_file=os.getenv("NAT_CONFIG_FILE", "configs/runai_rca_engine.yml").strip(),
        # Run analysis through the in-process NAT engine.
        enable_nat_runtime=_bool_env("ENABLE_NAT_RUNTIME", True),
        typedb_address=os.getenv("TYPEDB_ADDRESS", "").strip(),
        typedb_database=os.getenv("TYPEDB_DATABASE", "runai_rca").strip(),
        typedb_username=os.getenv("TYPEDB_USERNAME", "admin").strip(),
        typedb_password=os.getenv("TYPEDB_PASSWORD", "password").strip(),
        typedb_tls_enabled=_bool_env("TYPEDB_TLS_ENABLED", False),
        typedb_timeout_seconds=_int_env("TYPEDB_TIMEOUT_SECONDS", 60),
        enable_typedb=_bool_env("ENABLE_TYPEDB", False),
        enable_investigation_loop=_bool_env("ENABLE_INVESTIGATION_LOOP", False),
        # Generous by default: give the investigation loop room to keep digging
        # (more "opportunity to think"), not just more time per step.
        max_investigation_steps=max(1, _int_env("MAX_INVESTIGATION_STEPS", 12)),
        # Re-analysis (after the first top cause is refuted) gets a generous
        # investigation budget of its own — accuracy over speed.
        max_reanalysis_steps=max(1, _int_env("MAX_REANALYSIS_STEPS", 6)),
        analysis_token_budget=max(0, _int_env("ANALYSIS_TOKEN_BUDGET", 0)),
        # Per-collector autonomous drill-down: each evidence agent gets its own LLM
        # loop with ONLY its domain's read-only tools (see services/drilldown.py).
        # LLM-gated and best-effort like the investigation loop.
        enable_agent_drilldown=_bool_env("ENABLE_AGENT_DRILLDOWN", False),
        drilldown_max_steps=max(1, _int_env("DRILLDOWN_MAX_STEPS", 6)),
        # Overall hard cap on one analysis: agents get generous per-step time above,
        # but the whole run always finishes within this budget. (0 = no overall cap.)
        # Owner priority is accuracy over latency; the backend's
        # AGENT_REQUEST_TIMEOUT_SECONDS must stay above this (deadline + 60s).
        analysis_deadline_seconds=max(0, _int_env("ANALYSIS_DEADLINE_SECONDS", 1500)),
        max_investigation_iterations=_nonnegative_int_env("MAX_INVESTIGATION_ITERATIONS", 2),
    )
