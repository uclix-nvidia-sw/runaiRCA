from __future__ import annotations

import pytest

from app.config import load_settings
from app.knowledge import DEFAULT_FAMILIES, KnowledgeRegistry, validate_runtime_knowledge


class _Response:
    def __init__(self, status_code: int, payload: object | None = None, etag: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = {"ETag": etag} if etag else {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError("bad status", request=None, response=None)

    def json(self) -> object:
        return self._payload


class _Client:
    responses: list[_Response] = []
    headers: list[dict[str, str]] = []

    def __init__(self, **_kwargs: object) -> None:
        pass

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def get(self, _url: str, *, headers: dict[str, str]) -> _Response:
        self.__class__.headers.append(headers)
        return self.__class__.responses.pop(0)


def _snapshot(*, revision: str = "r1", keyword: str = "runtime marker") -> dict[str, object]:
    return {
        "revision": revision,
        "packages": [
            {
                "package_id": "pkg-1",
                "state": "active",
                "compiled": {
                    "failure_modes": [
                        {
                            "family": "runtime_family",
                            "symptoms": [
                                {
                                    "name": "Runtime symptom",
                                    "keywords": [keyword],
                                    "actions": ["inspect runtime"],
                                }
                            ],
                        }
                    ],
                    "known_issues": [
                        {"issue": "Runtime issue", "keywords": [keyword], "actions": []}
                    ],
                },
            }
        ],
    }


@pytest.mark.asyncio
async def test_registry_refresh_uses_etag_and_keeps_last_valid_snapshot(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    _Client.responses = [
        _Response(200, _snapshot(), '"r1"'),
        _Response(200, {"revision": "bad", "packages": [{"state": "candidate"}]}),
        _Response(304),
    ]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is True
    assert registry.health()["loaded_revision"] == "r1"
    assert await registry.refresh() is False
    assert registry.health()["loaded_revision"] == "r1"
    assert registry.health()["last_sync_error"]
    assert _Client.headers[1]["If-None-Match"] == '"r1"'

    assert await registry.refresh() is False
    assert registry.health()["loaded_revision"] == "r1"
    assert registry.health()["last_sync_error"] is None


@pytest.mark.asyncio
async def test_registry_modes_merge_only_approved_snapshot(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    _Client.responses = [_Response(200, _snapshot())]
    _Client.headers = []
    baseline_modes = {
        "runtime_family": [
            {"symptom": "Runtime symptom", "keywords": ["baseline marker"], "actions": []}
        ]
    }
    baseline_issues = [{"issue": "Runtime issue", "keywords": ["baseline marker"]}]

    shadow = KnowledgeRegistry(mode="shadow", snapshot_url="http://backend/snapshot")
    assert await shadow.refresh() is True
    assert (
        shadow.failure_modes(baseline_modes)["runtime_family"][0]["keywords"]
        == ["baseline marker"]
    )

    _Client.responses = [_Response(200, _snapshot())]
    assist = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")
    await assist.refresh()
    assert (
        assist.failure_modes(baseline_modes)["runtime_family"][0]["keywords"]
        == ["baseline marker"]
    )
    assert assist.known_issues(baseline_issues)[0]["keywords"] == ["baseline marker"]
    assert assist.failure_modes({}) == {}
    assert assist.known_issues([]) == []
    assert assist.provisional_catalogs()["failure_modes"]["runtime_family"][0]["keywords"] == [
        "runtime marker"
    ]
    assert assist.health()["active_package_ids"] == ["pkg-1"]

    _Client.responses = [_Response(200, _snapshot())]
    authoritative = KnowledgeRegistry(mode="authoritative", snapshot_url="http://backend/snapshot")
    await authoritative.refresh()
    assert (
        authoritative.failure_modes(baseline_modes)["runtime_family"][0]["keywords"]
        == ["runtime marker"]
    )
    assert authoritative.known_issues(baseline_issues)[0]["keywords"] == ["runtime marker"]


@pytest.mark.asyncio
async def test_registry_rejects_raw_case_snapshot_payload(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    _Client.responses = [
        _Response(
            200,
            {
                "revision": "raw-case",
                "packages": [
                    {
                        "package_id": "pkg-raw",
                        "status": "active",
                        "payload": {"incident_id": "INC-1", "artifacts": []},
                    }
                ],
            },
        )
    ]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is False
    assert registry.health()["loaded_revision"] is None
    assert "no compiled knowledge" in str(registry.health()["last_sync_error"])


@pytest.mark.asyncio
async def test_registry_accepts_backend_active_payload_compiled_fixture(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    _Client.responses = [
        _Response(
            200,
            {
                "revision": "compiled-package",
                "packages": [
                    {
                        "package_id": "KPK-case-1",
                        "status": "active",
                        "candidate_id": "KNC-case-1",
                        "payload": {
                            "case_id": "CASE-1",
                            "compiled": {
                                "failure_modes": [
                                    {
                                        "family": "runtime_family",
                                        "symptoms": [
                                            {
                                                "name": "Sanitized mechanism",
                                                "keywords": ["sanitized predicate"],
                                                "actions": ["inspect workload"],
                                            }
                                        ],
                                    }
                                ]
                            },
                        },
                    }
                ],
            },
        )
    ]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is True
    loaded = registry.provisional_catalogs()["failure_modes"]
    assert loaded["runtime_family"][0]["keywords"] == ["sanitized predicate"]


@pytest.mark.asyncio
async def test_assist_exposes_safe_probe_template_ids_without_changing_ranking(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    payload = _snapshot()
    payload["packages"][0]["compiled"]["probe_template_ids"] = {
        "runtime_family": [
            "k8s_troubleshooting:scheduling_capacity:p01",
            "k8s_troubleshooting:scheduling_capacity:p01",
        ]
    }
    _Client.responses = [_Response(200, payload)]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is True
    assert registry.failure_modes({}) == {}
    assert registry.probe_template_ids_for_family("runtime_family") == [
        "k8s_troubleshooting:scheduling_capacity:p01",
    ]
    assert registry.probe_template_ids_for_family("runtime_family", include_assist=False) == []
    assert registry.health()["probe_template_families"] == ["runtime_family"]

    _Client.responses = [_Response(200, payload)]
    authoritative = KnowledgeRegistry(mode="authoritative", snapshot_url="http://backend/snapshot")
    assert await authoritative.refresh() is True
    assert authoritative.probe_template_ids_for_family("runtime_family") == [
        "k8s_troubleshooting:scheduling_capacity:p01",
    ]


@pytest.mark.asyncio
async def test_registry_rejects_probe_template_args_or_queries(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    payload = _snapshot()
    payload["packages"][0]["compiled"]["probe_template_ids"] = {
        "runtime_family": ["k8s.pod.logs?namespace=runai"]
    }
    _Client.responses = [_Response(200, payload)]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is False
    assert "safe identifier strings" in str(registry.health()["last_sync_error"])


@pytest.mark.asyncio
async def test_registry_rejects_unknown_probe_template_id(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    payload = _snapshot()
    payload["packages"][0]["compiled"]["probe_template_ids"] = {
        "runtime_family": ["unknown-probe-template-01"]
    }
    _Client.responses = [_Response(200, payload)]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is False
    assert "unknown bundled probe template IDs" in str(registry.health()["last_sync_error"])


def test_settings_default_runtime_snapshot_url_and_mode(monkeypatch) -> None:
    monkeypatch.setenv("BACKEND_URL", "http://backend/")
    monkeypatch.setenv("DYNAMIC_KNOWLEDGE_MODE", "authoritative")
    settings = load_settings()

    assert settings.runtime_knowledge_url == "http://backend/api/v1/knowledge/runtime-snapshot"
    assert settings.dynamic_knowledge_mode == "authoritative"


def test_validate_runtime_knowledge_normalizes_active_compiled_package() -> None:
    package = _snapshot()["packages"][0]

    result = validate_runtime_knowledge(package)

    assert result["valid"] is True
    assert result["errors"] == []
    assert result["normalized"]["active_package_ids"] == ["pkg-1"]
    assert (
        result["normalized"]["failure_modes"]["runtime_family"][0]["symptom"]
        == "Runtime symptom"
    )


def test_internal_validation_route_uses_registry_validator() -> None:
    from app.main import app

    route = next(route for route in app.routes if route.path == "/knowledge/validate")
    response = route.endpoint(_snapshot())

    assert response["valid"] is True
    assert response["normalized"]["revision"] == "r1"


def test_family_catalog_route_exposes_selectable_output_families() -> None:
    from app.main import app

    route = next(route for route in app.routes if route.path == "/knowledge/families")

    assert route.endpoint() == {
        "families": [
            *DEFAULT_FAMILIES,
            "platform_version_bug",
            "expected_known_behavior",
            "insufficient_evidence",
        ]
    }


def test_validate_runtime_knowledge_returns_errors_without_mutating_registry() -> None:
    result = validate_runtime_knowledge({"package_id": "pkg-raw", "status": "active"})

    assert result == {
        "valid": False,
        "errors": ["package pkg-raw compiled content must be an object"],
        "normalized": None,
    }
