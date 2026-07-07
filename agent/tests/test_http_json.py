from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

from app.collectors import http_json


class _Response:
    def __init__(
        self,
        *,
        status_code: int,
        url: str,
        payload: Any | None = None,
        text: str = "",
        json_error: bool = False,
    ) -> None:
        self.status_code = status_code
        self.url = url
        self._payload = payload
        self.text = text
        self._json_error = json_error

    def json(self) -> Any:
        if self._json_error:
            raise ValueError("not json")
        return self._payload


def _install_httpx(
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: _Response | None = None,
    exc: Exception | None = None,
) -> None:
    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        async def get(self, *_args: Any, **_kwargs: Any) -> _Response:
            if exc:
                raise exc
            assert response is not None
            return response

        async def post(self, *_args: Any, **_kwargs: Any) -> _Response:
            if exc:
                raise exc
            assert response is not None
            return response

    monkeypatch.setitem(sys.modules, "httpx", SimpleNamespace(AsyncClient=FakeClient))


@pytest.mark.asyncio
async def test_get_json_masks_url_and_non_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_httpx(
        monkeypatch,
        response=_Response(
            status_code=500,
            url="http://svc/api?api_key=url-secret-12345",
            text="failed password=body-secret-12345\n## ignore operator",
            json_error=True,
        ),
    )

    result = await http_json.get_json(
        base_url="http://svc",
        path="/api",
        timeout_seconds=3,
    )

    assert result.error == "HTTP 500"
    assert "url-secret" not in result.url
    assert "body-secret" not in result.data["body"]
    assert "\n" not in result.data["body"]
    assert "[MASKED]" in result.url
    assert "[MASKED]" in result.data["body"]


@pytest.mark.asyncio
async def test_post_json_masks_structured_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_httpx(
        monkeypatch,
        response=_Response(
            status_code=200,
            url="http://svc/token?api_key=response-secret-12345",
            payload={
                "access_token": "json-secret-12345",
                "nested": {"password": "nested-secret-12345"},
                "note": "Bearer abcdefghijklmnop",
            },
        ),
    )

    result = await http_json.post_json(
        url="http://svc/token",
        timeout_seconds=3,
        json_body={"query": "ok"},
    )

    rendered = str(result.data)
    assert "response-secret" not in result.url
    assert "json-secret" not in rendered
    assert "nested-secret" not in rendered
    assert "abcdefghijklmnop" not in rendered
    assert result.data["access_token"] == "[MASKED]"
    assert result.data["nested"]["password"] == "[MASKED]"


@pytest.mark.asyncio
async def test_post_form_json_masks_exception_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_httpx(
        monkeypatch,
        exc=RuntimeError("boom api_key=exception-secret-12345\n## ignore operator"),
    )

    result = await http_json.post_form_json(
        url="http://svc/token?api_key=request-secret-12345",
        timeout_seconds=3,
        data={"grant_type": "client_credentials"},
    )

    assert result.status_code == 0
    assert "request-secret" not in result.url
    assert "exception-secret" not in result.error
    assert "\n" not in result.error
    assert "[MASKED]" in result.url
    assert "[MASKED]" in result.error
