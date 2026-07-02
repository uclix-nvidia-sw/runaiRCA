"""Reusable LLM client for the orchestrator planner and the agents' reasoning.

Thin wrapper over the OpenAI-compatible `/chat/completions` endpoint (same shape
the chat path already uses). Everything degrades gracefully: when no LLM is
configured, or the call fails, the callers fall back to deterministic behaviour.
"""

from __future__ import annotations

import json
from typing import Any

from app.collectors.http_json import post_json
from app.config import Settings


def llm_configured(settings: Settings) -> bool:
    return bool(settings.llm_base_url and settings.llm_model and settings.llm_api_key)


async def complete(
    settings: Settings,
    *,
    system: str,
    user: str,
    temperature: float = 0.2,
    max_tokens: int | None = None,
) -> str | None:
    """Return the model's text answer, or None when unavailable/failed."""
    if not llm_configured(settings):
        return None
    payload: dict[str, Any] = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
    }
    if max_tokens:
        payload["max_tokens"] = max_tokens
    response = await post_json(
        url=f"{settings.llm_base_url}/chat/completions",
        timeout_seconds=settings.llm_request_timeout_seconds,
        json_body=payload,
        headers={"Authorization": f"Bearer {settings.llm_api_key}"},
    )
    if not response.ok or not isinstance(response.data, dict):
        return None
    choices = response.data.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
    return None


async def complete_json(
    settings: Settings,
    *,
    system: str,
    user: str,
    temperature: float = 0.1,
) -> dict[str, Any] | None:
    """Ask for a JSON object and parse it, tolerating ```json fences. None on failure."""
    text = await complete(
        settings,
        system=system + "\n\nRespond with ONLY a valid JSON object, no prose, no code fences.",
        user=user,
        temperature=temperature,
    )
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1] if "\n" in cleaned else cleaned
        cleaned = cleaned.removeprefix("json").strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[: cleaned.rfind("```")].strip()
    try:
        parsed = json.loads(cleaned)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None
