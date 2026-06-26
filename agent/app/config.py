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
    runai_base_url: str
    runai_bearer_token: str
    runai_client_id: str
    runai_client_secret: str
    runai_token_url: str
    runai_workloads_path: str
    runai_projects_path: str
    runai_queues_path: str
    runai_timeout_seconds: int
    prometheus_url: str
    prometheus_timeout_seconds: int
    prometheus_mcp_url: str
    loki_url: str
    loki_timeout_seconds: int
    loki_query_limit: int
    loki_mcp_url: str
    runai_log_namespaces: tuple[str, ...]
    postgres_dsn: str
    postgres_timeout_seconds: int
    troubleshooting_cases_file: str
    agent_souls_file: str
    masking_regex_list: tuple[str, ...]
    builtin_redaction_enabled: bool
    builtin_redaction_hash_mode: bool
    nat_config_file: str
    enable_nat_runtime: bool
    nat_timeout_seconds: int


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
        kubernetes_timeout_seconds=_int_env("KUBERNETES_TIMEOUT_SECONDS", 6),
        kubernetes_list_limit=max(1, _int_env("KUBERNETES_LIST_LIMIT", 50)),
        runai_base_url=os.getenv("RUNAI_BASE_URL", "").strip().rstrip("/"),
        runai_bearer_token=os.getenv("RUNAI_BEARER_TOKEN", "").strip(),
        runai_client_id=os.getenv("RUNAI_CLIENT_ID", "").strip(),
        runai_client_secret=os.getenv("RUNAI_CLIENT_SECRET", "").strip(),
        runai_token_url=os.getenv("RUNAI_TOKEN_URL", "").strip(),
        runai_workloads_path=os.getenv("RUNAI_WORKLOADS_PATH", "/api/v1/workloads").strip(),
        runai_projects_path=os.getenv("RUNAI_PROJECTS_PATH", "/api/v1/projects").strip(),
        runai_queues_path=os.getenv("RUNAI_QUEUES_PATH", "/api/v1/queues").strip(),
        runai_timeout_seconds=_int_env("RUNAI_TIMEOUT_SECONDS", 8),
        prometheus_url=os.getenv("PROMETHEUS_URL", "").strip().rstrip("/"),
        prometheus_timeout_seconds=_int_env("PROMETHEUS_TIMEOUT_SECONDS", 6),
        prometheus_mcp_url=os.getenv("PROMETHEUS_MCP_URL", "").strip().rstrip("/"),
        loki_url=os.getenv("LOKI_URL", "").strip().rstrip("/"),
        loki_timeout_seconds=_int_env("LOKI_TIMEOUT_SECONDS", 6),
        loki_query_limit=max(1, _int_env("LOKI_QUERY_LIMIT", 20)),
        loki_mcp_url=os.getenv("LOKI_MCP_URL", "").strip().rstrip("/"),
        runai_log_namespaces=_csv_env("RUNAI_LOG_NAMESPACES", ("runai", "runai-backend")),
        postgres_dsn=os.getenv("POSTGRES_DSN", "").strip(),
        postgres_timeout_seconds=_int_env("POSTGRES_TIMEOUT_SECONDS", 6),
        troubleshooting_cases_file=os.getenv(
            "TROUBLESHOOTING_CASES_FILE",
            "knowledge/troubleshooting_cases.md",
        ).strip(),
        agent_souls_file=os.getenv("AGENT_SOULS_FILE", "prompts/agent_souls.md").strip(),
        masking_regex_list=_json_string_list_env("MASKING_REGEX_LIST_JSON"),
        builtin_redaction_enabled=_bool_env("BUILTIN_REDACTION_ENABLED", True),
        builtin_redaction_hash_mode=_bool_env("BUILTIN_REDACTION_HASH_MODE", False),
        nat_config_file=os.getenv(
            "NAT_CONFIG_FILE", "configs/runai_rca_workflow.yml"
        ).strip(),
        enable_nat_runtime=_bool_env("ENABLE_NAT_RUNTIME", False),
        nat_timeout_seconds=_int_env("NAT_TIMEOUT_SECONDS", 180),
    )
