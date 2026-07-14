from __future__ import annotations

from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class OAuthTokenResponse:
    """OAuth response that never exposes its bearer in repr/log payloads."""

    url: str
    status_code: int
    token: str = field(default="", repr=False)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.token) and self.error is None and 200 <= self.status_code < 300


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


async def post_oauth_token(
    *,
    url: str,
    timeout_seconds: int,
    json_body: dict[str, Any] | None = None,
    form_data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    verify: bool | str = True,
) -> OAuthTokenResponse:
    """Exchange credentials and return only the raw bearer token.

    Normal collector responses are redacted before they leave this module. An
    OAuth token cannot go through that path because redaction intentionally
    turns it into ``[MASKED]``. This narrow helper extracts the token in memory,
    discards the rest of the raw response, and marks the token field
    ``repr=False`` so diagnostics cannot accidentally print it.
    """
    if (json_body is None) == (form_data is None):
        return OAuthTokenResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error="exactly one OAuth request body must be provided",
        )
    try:
        import httpx
    except ImportError:
        return OAuthTokenResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error="python.httpx is not installed",
        )

    try:
        async with httpx.AsyncClient(
            timeout=_client_timeout(timeout_seconds), verify=verify
        ) as client:
            if json_body is not None:
                response = await client.post(url, json=json_body, headers=headers)
            else:
                response = await client.post(url, data=form_data, headers=headers)
    except Exception as exc:  # noqa: BLE001 - auth failure is returned to caller.
        return OAuthTokenResponse(
            url=_safe_text(url, limit=2000),
            status_code=0,
            error=_safe_text(f"{exc.__class__.__name__}: {exc}", limit=1000),
        )

    token = ""
    if response.status_code < 400:
        try:
            token = _oauth_token_from_payload(response.json())
        except (TypeError, ValueError):
            token = ""
    error = None
    if response.status_code >= 400:
        error = f"HTTP {response.status_code}"
    elif not token:
        error = "missing access token"
    return OAuthTokenResponse(
        url=_safe_text(str(response.url), limit=2000),
        status_code=response.status_code,
        token=token,
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


def _oauth_token_from_payload(data: object) -> str:
    if not isinstance(data, dict):
        return ""
    for key in ("accessToken", "access_token", "token", "id_token"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _safe_text(value: str, *, limit: int) -> str:
    text = " ".join(build_masker(()).mask_text(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
