"""System collector must address the per-node agent by the node's InternalIP:
pod DNS cannot resolve bare node hostnames (http://dgx01:9095 failed with
'Name or service not known' in production)."""

from __future__ import annotations

import asyncio

import app.collectors.kubernetes as k8s
import app.collectors.system as system
from app.collectors.http_json import JsonResponse
from tests.test_orchestrator import make_settings


def test_node_internal_ip_resolves(monkeypatch) -> None:
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "token")

    async def _fake_get_json(**kwargs):
        assert kwargs["path"] == "/api/v1/nodes/dgx01"
        return JsonResponse(
            url="u",
            status_code=200,
            data={
                "status": {
                    "addresses": [
                        {"type": "Hostname", "address": "dgx01"},
                        {"type": "InternalIP", "address": "192.168.20.11"},
                    ]
                }
            },
        )

    monkeypatch.setattr(system, "get_json", _fake_get_json)
    ip = asyncio.run(system._node_internal_ip(make_settings(), "dgx01"))
    assert ip == "192.168.20.11"
    assert system._base_url_for_node("http://{node}:9095", ip) == "http://192.168.20.11:9095"


def test_node_internal_ip_falls_back_empty(monkeypatch) -> None:
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "token")

    async def _fake_get_json(**kwargs):
        return JsonResponse(url="u", status_code=403, error="HTTP 403")

    monkeypatch.setattr(system, "get_json", _fake_get_json)
    assert asyncio.run(system._node_internal_ip(make_settings(), "dgx01")) == ""


def test_node_internal_ip_without_token_is_empty(monkeypatch) -> None:
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "")
    assert asyncio.run(system._node_internal_ip(make_settings(), "dgx01")) == ""
