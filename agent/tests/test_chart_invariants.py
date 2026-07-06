"""Deploy-time guardrails: catch cross-component config drift and chart image
mistakes in CI, before they become production incidents.

Every assertion here encodes a bug that actually shipped:
- backend hung up its agent call (180s) while the agent worked to its 20-min
  deadline -> every long analysis was abandoned mid-flight.
- systemAgent.image.repository was the bare `python`, so global.imageRegistry
  rewrote a public base image into the private org -> ImagePullBackOff 403.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

VALUES = Path(__file__).parents[2] / "charts" / "runai-rca" / "values.yaml"
# Images we build and publish to the org registry — the ONLY repositories allowed
# to be short (unqualified), because global.imageRegistry is meant to prefix them.
OWN_IMAGES = {"runai-rca-agent", "runai-rca-backend", "runai-rca-frontend", "runai-rca-mcp"}


def _values() -> dict[str, Any]:
    return yaml.safe_load(VALUES.read_text(encoding="utf-8"))


def test_backend_agent_call_outlives_agent_deadline() -> None:
    v = _values()
    agent_deadline = int(v["agent"]["env"]["analysisDeadlineSeconds"])
    backend = v["backend"]["env"]
    assert int(backend["agentRequestTimeoutSeconds"]) > agent_deadline, (
        "backend.agentRequestTimeoutSeconds must exceed agent.analysisDeadlineSeconds: "
        "the agent works up to its deadline then returns a degraded report — if the "
        "backend hangs up first, the report is lost and the alert gets a useless fallback"
    )
    assert int(backend["manualAgentRequestTimeoutSeconds"]) > agent_deadline, (
        "backend.manualAgentRequestTimeoutSeconds must exceed agent.analysisDeadlineSeconds"
    )


def test_agent_step_ceilings_fit_inside_the_deadline() -> None:
    env = _values()["agent"]["env"]
    deadline = int(env["analysisDeadlineSeconds"])
    for key in ("llmRequestTimeoutSeconds", "natTimeoutSeconds"):
        assert int(env[key]) < deadline, (
            f"agent.env.{key} must stay below analysisDeadlineSeconds so a single "
            "hung step cannot eat the whole analysis budget"
        )


def _image_repos(node: Any, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        repo = node.get("repository")
        if isinstance(repo, str) and repo:
            found.append((path or "<root>", repo))
        for key, child in node.items():
            found.extend(_image_repos(child, f"{path}.{key}" if path else str(key)))
    return found


def test_third_party_images_are_fully_qualified() -> None:
    # global.imageRegistry prefixes SHORT repos (our own images). Any third-party
    # image left short gets rewritten into the private org and 403s on pull.
    for path, repo in _image_repos(_values()):
        first = repo.split("/", 1)[0]
        qualified = "." in first or ":" in first or first == "localhost"
        assert qualified or repo in OWN_IMAGES, (
            f"{path}: image repository {repo!r} is unqualified but not one of our own "
            f"images {sorted(OWN_IMAGES)} — global.imageRegistry would rewrite it into "
            "the private org where it does not exist (ImagePullBackOff). Fully qualify "
            "it (e.g. docker.io/library/...)"
        )