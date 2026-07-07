from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.masking import build_masker


@dataclass(frozen=True)
class JsonResponse:
    url: str
    status_code: int
    data: Any | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 300


async def get_json(
    *,
    base_url: str,
    path: str,
    timeout_seconds: int,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    verify: bool | str = True,
) -> JsonResponse:
    try:
        import httpx
    except ImportError:
        return JsonResponse(
            url=_safe_text(_join_url(base_url, path), limit=2000),
            status_code=0,
            error="python.httpx is not installed",
        )

    url = _join_url(base_url, path)
    try:
        async with httpx.AsyncClient(
            timeout=_client_timeout(timeout_seconds), verify=verify
        ) as client:
            response = await client.get(url, params=params, headers=headers)
    except Exception as exc:  # noqa: BLE001 - collectors report diagnostics, not failures.
        return JsonResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error=_safe_text(f"{exc.__class__.__name__}: {exc}", limit=1000),
        )

    data = _response_data(response)

    error = None
    if response.status_code >= 400:
        error = f"HTTP {response.status_code}"
    return JsonResponse(
        url=_safe_text(str(response.url), limit=2000),
        status_code=response.status_code,
        data=data,
        error=error,
    )


async def post_form_json(
    *,
    url: str,
    timeout_seconds: int,
    data: dict[str, Any],
    headers: dict[str, str] | None = None,
    verify: bool | str = True,
) -> JsonResponse:
    try:
        import httpx
    except ImportError:
        return JsonResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error="python.httpx is not installed",
        )

    try:
        async with httpx.AsyncClient(
            timeout=_client_timeout(timeout_seconds), verify=verify
        ) as client:
            response = await client.post(url, data=data, headers=headers)
    except Exception as exc:  # noqa: BLE001 - collectors report diagnostics, not failures.
        return JsonResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error=_safe_text(f"{exc.__class__.__name__}: {exc}", limit=1000),
        )

    payload = _response_data(response)

    error = None
    if response.status_code >= 400:
        error = f"HTTP {response.status_code}"
    return JsonResponse(
        url=_safe_text(str(response.url), limit=2000),
        status_code=response.status_code,
        data=payload,
        error=error,
    )


async def post_json(
    *,
    url: str,
    timeout_seconds: int,
    json_body: dict[str, Any],
    headers: dict[str, str] | None = None,
    verify: bool | str = True,
) -> JsonResponse:
    try:
        import httpx
    except ImportError:
        return JsonResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error="python.httpx is not installed",
        )

    try:
        async with httpx.AsyncClient(
            timeout=_client_timeout(timeout_seconds), verify=verify
        ) as client:
            response = await client.post(url, json=json_body, headers=headers)
    except Exception as exc:  # noqa: BLE001 - collectors report diagnostics, not failures.
        return JsonResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error=_safe_text(f"{exc.__class__.__name__}: {exc}", limit=1000),
        )

    payload = _response_data(response)

    error = None
    if response.status_code >= 400:
        error = f"HTTP {response.status_code}"
    return JsonResponse(
        url=_safe_text(str(response.url), limit=2000),
        status_code=response.status_code,
        data=payload,
        error=error,
    )


def compact(value: Any, *, limit: int = 5) -> Any:
    if isinstance(value, dict):
        return {key: compact(child, limit=limit) for key, child in value.items()}
    if isinstance(value, list):
        trimmed = [compact(child, limit=limit) for child in value[:limit]]
        if len(value) > limit:
            trimmed.append({"truncated": len(value) - limit})
        return trimmed
    return value


def _client_timeout(timeout_seconds: int) -> float | None:
    """<=0 means 'no timeout' (unlimited) — let the caller wait as long as it needs.

    Used so an LLM/agent request configured with timeout 0 is never cut off mid-
    thought; a positive value keeps the usual bound (e.g. for data collectors).
    """
    return timeout_seconds if timeout_seconds and timeout_seconds > 0 else None


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _response_data(response: Any) -> Any:
    try:
        return build_masker(()).mask_object(response.json())
    except ValueError:
        return {"body": _safe_text(response.text, limit=1000)}


def _safe_text(value: str, *, limit: int) -> str:
    text = " ".join(build_masker(()).mask_text(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
