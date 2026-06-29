from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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
            url=_join_url(base_url, path),
            status_code=0,
            error="python.httpx is not installed",
        )

    url = _join_url(base_url, path)
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, verify=verify) as client:
            response = await client.get(url, params=params, headers=headers)
    except Exception as exc:  # noqa: BLE001 - collectors report diagnostics, not failures.
        return JsonResponse(url=url, status_code=0, error=f"{exc.__class__.__name__}: {exc}")

    try:
        data: Any = response.json()
    except ValueError:
        data = {"body": response.text[:1000]}

    error = None
    if response.status_code >= 400:
        error = f"HTTP {response.status_code}"
    return JsonResponse(
        url=str(response.url),
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
        return JsonResponse(url=url, status_code=0, error="python.httpx is not installed")

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, verify=verify) as client:
            response = await client.post(url, data=data, headers=headers)
    except Exception as exc:  # noqa: BLE001 - collectors report diagnostics, not failures.
        return JsonResponse(url=url, status_code=0, error=f"{exc.__class__.__name__}: {exc}")

    try:
        payload: Any = response.json()
    except ValueError:
        payload = {"body": response.text[:1000]}

    error = None
    if response.status_code >= 400:
        error = f"HTTP {response.status_code}"
    return JsonResponse(
        url=str(response.url),
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
        return JsonResponse(url=url, status_code=0, error="python.httpx is not installed")

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, verify=verify) as client:
            response = await client.post(url, json=json_body, headers=headers)
    except Exception as exc:  # noqa: BLE001 - collectors report diagnostics, not failures.
        return JsonResponse(url=url, status_code=0, error=f"{exc.__class__.__name__}: {exc}")

    try:
        payload: Any = response.json()
    except ValueError:
        payload = {"body": response.text[:1000]}

    error = None
    if response.status_code >= 400:
        error = f"HTTP {response.status_code}"
    return JsonResponse(
        url=str(response.url),
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


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"
