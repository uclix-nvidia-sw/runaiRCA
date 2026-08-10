from __future__ import annotations

import pytest

from app.config import load_settings
from app.knowledge import (
    DEFAULT_FAMILIES,
    KnowledgeRegistry,
    _bundled_probe_template_ids,
    match_failure_mode_symptoms,
    validate_runtime_knowledge,
)
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.pipeline import ReportKnowledge
from app.services.root_cause_ranking import RankedCause


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


def _snapshot(
    *,
    revision: str = "r1",
    keyword: str = "runtime marker",
    status: str = "active",
    package_id: str = "pkg-1",
    family: str = "workload_runtime_error",
) -> dict[str, object]:
    return {
        "revision": revision,
        "packages": [
            {
                "package_id": package_id,
                "state": status,
                "compiled": {
                    "failure_modes": [
                        {
                            "family": family,
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
async def test_registry_modes_apply_activation_ladder(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    _Client.responses = [_Response(200, _snapshot())]
    _Client.headers = []
    baseline_modes = {
        "workload_runtime_error": [
            {"symptom": "Runtime symptom", "keywords": ["baseline marker"], "actions": []}
        ]
    }
    baseline_issues = [{"issue": "Runtime issue", "keywords": ["baseline marker"]}]

    _Client.responses = [_Response(200, _snapshot())]
    assist = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")
    await assist.refresh()
    assert (
        assist.failure_modes(baseline_modes)["workload_runtime_error"][0]["keywords"]
        == ["runtime marker"]
    )
    assert assist.known_issues(baseline_issues)[0]["keywords"] == ["runtime marker"]
    assert match_failure_mode_symptoms(
        assist.failure_modes(baseline_modes), "runtime marker"
    )[0][1]["runtime_status"] == "active"
    assert assist.provisional_catalogs()["failure_modes"]["workload_runtime_error"][0]["keywords"] == [
        "runtime marker"
    ]
    assert assist.health()["active_package_ids"] == ["pkg-1"]

    _Client.responses = [
        _Response(
            200,
            {
                "revision": "r-shadow",
                "packages": [
                    _snapshot()["packages"][0],
                    _snapshot(
                        revision="r-shadow",
                        keyword="shadow marker",
                        status="shadow",
                        package_id="pkg-shadow",
                        family="gpu_hardware_error",
                    )["packages"][0],
                ],
            },
        )
    ]
    assist_with_shadow = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")
    await assist_with_shadow.refresh()
    assist_catalog = assist_with_shadow.failure_modes(baseline_modes)
    assert "gpu_hardware_error" not in assist_catalog
    assert assist_with_shadow.shadow_hints("shadow marker")[0][1]["runtime_status"] == "shadow"

    _Client.responses = [
        _Response(
            200,
            {
                "revision": "r-shadow",
                "packages": [
                    _snapshot()["packages"][0],
                    _snapshot(
                        keyword="shadow marker",
                        status="shadow",
                        package_id="pkg-shadow",
                        family="gpu_hardware_error",
                    )["packages"][0],
                ],
            },
        )
    ]
    authoritative = KnowledgeRegistry(mode="authoritative", snapshot_url="http://backend/snapshot")
    await authoritative.refresh()
    assert (
        authoritative.failure_modes(baseline_modes)["workload_runtime_error"][0]["keywords"]
        == ["runtime marker"]
    )
    assert {
        symptom["runtime_status"]
        for symptoms in authoritative.failure_modes({}).values()
        for symptom in symptoms
    } == {"active", "shadow"}
    assert match_failure_mode_symptoms(
        authoritative.failure_modes({}), "shadow marker"
    )[0][0] == "gpu_hardware_error"

    detail = pipeline._detail_from(
                 AlertAnalysisRequest(
            alert=Alert(
                labels={"alertname": "RuntimeKnowledgeAlert"},
                annotations={"summary": "runtime marker and shadow marker"},
            )
        ),
                 [],
                 [],
                 root_cause_candidates=[
            RankedCause(family="workload_runtime_error", confidence="medium", score=7.0)
        ],
                 runtime_knowledge_hints=assist_with_shadow.shadow_hints("shadow marker"),
                 knowledge=ReportKnowledge(failure_modes=assist_catalog),
             )
    assert "package pkg-1; family workload_runtime_error; matched symptom Runtime symptom; status active" in detail
    assert "### Learned Knowledge (Pending Activation)" in detail
    assert "package pkg-shadow family gpu_hardware_error" in detail

    _Client.responses = [_Response(200, {"revision": "empty", "packages": []})]
    empty = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")
    await empty.refresh()
    assert empty.failure_modes(baseline_modes) == baseline_modes
    assert empty.known_issues(baseline_issues) == baseline_issues
    assert empty.shadow_hints("runtime marker") == []


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
                                        "family": "workload_runtime_error",
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
    assert loaded["workload_runtime_error"][0]["keywords"] == ["sanitized predicate"]


@pytest.mark.asyncio
async def test_assist_exposes_safe_probe_template_ids_without_changing_ranking(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    payload = _snapshot()
    payload["packages"][0]["compiled"]["probe_template_ids"] = {
        "workload_runtime_error": [
            "k8s_troubleshooting:scheduling_capacity:p01",
            "k8s_troubleshooting:scheduling_capacity:p01",
        ]
    }
    _Client.responses = [_Response(200, payload)]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is True
    assert registry.failure_modes({})["workload_runtime_error"][0]["keywords"] == ["runtime marker"]
    assert registry.probe_template_ids_for_family("workload_runtime_error") == [
        "k8s_troubleshooting:scheduling_capacity:p01",
    ]
    assert registry.probe_template_ids_for_family("workload_runtime_error", include_assist=False) == []
    assert registry.health()["probe_template_families"] == ["workload_runtime_error"]

    _Client.responses = [_Response(200, payload)]
    authoritative = KnowledgeRegistry(mode="authoritative", snapshot_url="http://backend/snapshot")
    assert await authoritative.refresh() is True
    assert authoritative.probe_template_ids_for_family("workload_runtime_error") == [
        "k8s_troubleshooting:scheduling_capacity:p01",
    ]


@pytest.mark.asyncio
async def test_registry_rejects_probe_template_args_or_queries(monkeypatch) -> None:
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    payload = _snapshot()
    payload["packages"][0]["compiled"]["probe_template_ids"] = {
        "workload_runtime_error": ["k8s.pod.logs?namespace=runai"]
    }
    _Client.responses = [_Response(200, payload)]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is False
    assert "safe identifier strings" in str(registry.health()["last_sync_error"])


@pytest.mark.asyncio
async def test_registry_drops_unknown_probe_template_id_but_keeps_package(monkeypatch) -> None:
    # The walk resolves its runbook from TypeDB first, so a probe a run really
    # executed can be absent from the bundled YAML. That must cost the probe
    # reference, not the whole learned package.
    monkeypatch.setattr("app.knowledge.httpx.AsyncClient", _Client)
    known = sorted(_bundled_probe_template_ids())[0]
    payload = _snapshot()
    payload["packages"][0]["compiled"]["probe_template_ids"] = {
        "workload_runtime_error": ["unknown-probe-template-01", known],
        "image_pull_error": ["unknown-probe-template-02"],
    }
    _Client.responses = [_Response(200, payload)]
    _Client.headers = []
    registry = KnowledgeRegistry(mode="assist", snapshot_url="http://backend/snapshot")

    assert await registry.refresh() is True
    assert registry.health()["last_sync_error"] in (None, "")
    assert registry.probe_template_ids_for_family("workload_runtime_error") == [known]
    # A family left with no resolvable probe is dropped rather than kept empty.
    assert registry.probe_template_ids_for_family("image_pull_error") == []


def test_settings_default_runtime_snapshot_url_and_mode(monkeypatch) -> None:
    monkeypatch.setenv("BACKEND_URL", "http://backend/")
    monkeypatch.setenv("DYNAMIC_KNOWLEDGE_MODE", "authoritative")
    settings = load_settings()

    assert settings.runtime_knowledge_url == "http://backend/api/v1/knowledge/runtime-snapshot"
    assert settings.dynamic_knowledge_mode == "authoritative"


def test_settings_default_dynamic_knowledge_mode_is_assist(monkeypatch) -> None:
    monkeypatch.delenv("DYNAMIC_KNOWLEDGE_MODE", raising=False)

    assert load_settings().dynamic_knowledge_mode == "assist"


def test_validate_runtime_knowledge_normalizes_active_compiled_package() -> None:
    package = _snapshot()["packages"][0]

    result = validate_runtime_knowledge(package)

    assert result["valid"] is True
    assert result["errors"] == []
    assert result["normalized"]["active_package_ids"] == ["pkg-1"]
    assert (
        result["normalized"]["failure_modes"]["workload_runtime_error"][0]["symptom"]
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
        # DEFAULT_FAMILIES already carries platform_version_bug and
        # expected_known_behavior (they are catalog families now, not just
        # known-issue-only labels) — appending them again would assert a
        # duplicate the real route never produces (evaluation_families
        # dedupes via dict.fromkeys).
        "families": [*DEFAULT_FAMILIES, "insufficient_evidence"]
    }


def test_validate_runtime_knowledge_returns_errors_without_mutating_registry() -> None:
    result = validate_runtime_knowledge({"package_id": "pkg-raw", "status": "active"})

    assert result == {
        "valid": False,
        "errors": ["package pkg-raw compiled content must be an object"],
        "normalized": None,
    }


def test_non_catalog_family_package_fails_validation() -> None:
    snapshot = _snapshot()
    package = snapshot["packages"][0]
    package["compiled"]["failure_modes"][0]["family"] = "workload_startup_image_failure"

    result = validate_runtime_knowledge(package)

    assert result["valid"] is False
    assert any("closed catalog" in str(error) for error in result.get("errors", []))


def test_null_actions_and_probe_ids_validate_as_empty() -> None:
    """A matcher-only package must stay promotable.

    The backend serves candidate payloads that can carry `null` for an empty
    action or probe list, and null means "none recorded" — not a malformed
    package. Rejecting it made every candidate whose evaluation recorded no
    effective action permanently unpromotable.
    """
    snapshot = _snapshot()
    package = snapshot["packages"][0]
    symptom = package["compiled"]["failure_modes"][0]["symptoms"][0]
    symptom["actions"] = None
    symptom["actions_ko"] = None
    package["compiled"]["probe_template_ids"] = {"workload_runtime_error": None}

    result = validate_runtime_knowledge(package)

    assert result["valid"] is True, result["errors"]
    compiled = result["normalized"]["failure_modes"]["workload_runtime_error"][0]
    assert compiled["actions"] == []
    assert compiled["actions_ko"] == []


def test_shadow_package_probes_stay_out_of_the_plan():
    """Shadow is observe-only: its probes must not steer the next investigation."""
    from app.knowledge import KnowledgeRegistry, _validate_approved_snapshot

    snapshot = _validate_approved_snapshot(
        {
            "revision": "rev-shadow-probe",
            "packages": [
                {
                    "package_id": "KPKG-shadow",
                    "state": "shadow",
                    "compiled": {"probe_template_ids": {"workload_runtime_error": ["k8s_troubleshooting:admission_webhook_failure:p01"]}},
                },
                {
                    "package_id": "KPKG-active",
                    "state": "active",
                    "compiled": {"probe_template_ids": {"workload_runtime_error": ["k8s_troubleshooting:api_server_failure:p01"]}},
                },
            ],
        }
    )
    registry = KnowledgeRegistry(mode="assist")
    registry._snapshot = snapshot
    assert registry.probe_template_ids_for_family("workload_runtime_error") == ["k8s_troubleshooting:api_server_failure:p01"]


def test_novel_family_package_is_accepted_as_matcher_only():
    """Open-world knowledge may match; is_matcher_only_family keeps it off the headline."""
    from app.knowledge import _validate_approved_snapshot, is_matcher_only_family

    snapshot = _validate_approved_snapshot(
        {
            "revision": "rev-novel",
            "packages": [
                {
                    "package_id": "KPKG-novel",
                    "state": "active",
                    "compiled": {
                        "failure_modes": [
                            {
                                "family": "novel_gpu_fabric_flap_ab12cd34",
                                "symptoms": [
                                    {
                                        "name": "fabric link flaps under sustained load",
                                        "keywords": ["nvlink", "fabricmanager"],
                                        "actions": ["reseat the affected link"],
                                    }
                                ],
                            }
                        ]
                    },
                }
            ],
        }
    )
    assert list(snapshot.failure_modes) == ["novel_gpu_fabric_flap_ab12cd34"]
    assert is_matcher_only_family("novel_gpu_fabric_flap_ab12cd34")


def test_one_unusable_package_does_not_sink_the_snapshot():
    """A single bad row used to freeze the whole runtime revision."""
    from app.knowledge import _validate_approved_snapshot

    good = {
        "package_id": "KPKG-good",
        "state": "active",
        "compiled": {
            "failure_modes": [
                {
                    "family": "workload_runtime_error",
                    "symptoms": [{"name": "oom", "keywords": ["oomkilled"], "actions": []}],
                }
            ]
        },
    }
    bad = {
        "package_id": "KPKG-legacy",
        "state": "active",
        "compiled": {
            "failure_modes": [
                {
                    "family": "storage_io_error_legacy",
                    "symptoms": [{"name": "x", "keywords": ["y"], "actions": []}],
                }
            ]
        },
    }
    snapshot = _validate_approved_snapshot(
        {"revision": "rev-mixed", "packages": [good, bad]}, isolate_failures=True
    )
    assert snapshot.active_package_ids == ("KPKG-good",)
    assert list(snapshot.failure_modes) == ["workload_runtime_error"]

    # Every package unusable is a bad snapshot, not a partial one: the caller
    # must keep the last good revision rather than install an empty catalog.
    with pytest.raises(ValueError):
        _validate_approved_snapshot(
            {"revision": "rev-bad", "packages": [bad]}, isolate_failures=True
        )
    # Approval-time validation stays strict.
    with pytest.raises(ValueError):
        _validate_approved_snapshot({"revision": "rev-bad", "packages": [bad]})
