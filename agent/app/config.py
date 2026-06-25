from __future__ import annotations

import os
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


@dataclass(frozen=True)
class Settings:
    port: int
    log_level: str
    language: str
    runai_base_url: str
    runai_client_id: str
    runai_client_secret: str
    runai_timeout_seconds: int
    prometheus_url: str
    prometheus_timeout_seconds: int
    loki_url: str
    loki_timeout_seconds: int
    postgres_dsn: str
    postgres_timeout_seconds: int
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
        runai_base_url=os.getenv("RUNAI_BASE_URL", "").strip().rstrip("/"),
        runai_client_id=os.getenv("RUNAI_CLIENT_ID", "").strip(),
        runai_client_secret=os.getenv("RUNAI_CLIENT_SECRET", "").strip(),
        runai_timeout_seconds=_int_env("RUNAI_TIMEOUT_SECONDS", 8),
        prometheus_url=os.getenv("PROMETHEUS_URL", "").strip().rstrip("/"),
        prometheus_timeout_seconds=_int_env("PROMETHEUS_TIMEOUT_SECONDS", 6),
        loki_url=os.getenv("LOKI_URL", "").strip().rstrip("/"),
        loki_timeout_seconds=_int_env("LOKI_TIMEOUT_SECONDS", 6),
        postgres_dsn=os.getenv("POSTGRES_DSN", "").strip(),
        postgres_timeout_seconds=_int_env("POSTGRES_TIMEOUT_SECONDS", 6),
        nat_config_file=os.getenv(
            "NAT_CONFIG_FILE", "configs/runai_rca_workflow.yml"
        ).strip(),
        enable_nat_runtime=_bool_env("ENABLE_NAT_RUNTIME", False),
        nat_timeout_seconds=_int_env("NAT_TIMEOUT_SECONDS", 180),
    )
