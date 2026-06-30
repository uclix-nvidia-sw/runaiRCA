from __future__ import annotations

from pathlib import Path

_FALLBACK_AGENT_SOULS = """# Run:AI RCA Agent Role Contracts

RunAI Agent owns Run:ai API workload, project, queue, quota, and scheduling
context. It does not run the runai CLI by default and does not inspect
Run:ai pods or logs directly.

Kubernetes Agent owns pods, events, nodes, and Kubernetes scheduling blockers.
Prometheus Agent owns metrics. Loki Agent owns workload and Run:ai
control-plane/backend logs. Postgres Agent owns the RCA store, pgvector,
feedback, comments, and memory health. Analysis Agent owns the dashboard RCA
verdict, confidence, impact, missing data, recommended remediation actions, and
prevention guidance. Analysis must stay read-only, evidence-backed, explicit
about missing data, and masked for sensitive values.
"""


def load_agent_souls(path: str) -> str:
    for candidate in _candidate_paths(path):
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return _FALLBACK_AGENT_SOULS.strip()


def agent_role_coverage_lines() -> list[str]:
    return [
        "- **analysis**: KubeRCA-style RCA verdict, confidence, impact, missing-data, "
        "recommended remediation actions, prevention, and dashboard summary.",
        "- **runai**: Run:ai API workload, project, queue, quota, and scheduling "
        "context; no CLI by default.",
        "- **kubernetes**: workload pods/events, Run:ai control-plane pod health, "
        "node conditions, and Kubernetes scheduling blockers.",
        "- **prometheus**: queue/project GPU metrics, pending/restart/resource "
        "signals, and absent metric series.",
        "- **loki**: workload logs plus `runai` and `runai-backend` control-plane/backend logs.",
        "- **postgres**: RCA store, pgvector, embeddings, feedback, comments, "
        "and persistence health.",
    ]


def _candidate_paths(path: str) -> list[Path]:
    configured = Path(path)
    if configured.is_absolute():
        return [configured]

    project_root = Path(__file__).resolve().parents[1]
    return [
        Path.cwd() / configured,
        project_root / configured,
    ]
