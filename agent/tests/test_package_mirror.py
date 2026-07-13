from __future__ import annotations

import inspect

from ontology import mirror_packages


def test_mirror_error_is_bounded_and_does_not_persist_exception_text() -> None:
    secret = "postgres://operator:secret-token@example.invalid/rca"
    message = mirror_packages._safe_error(RuntimeError(secret))

    assert message == "TypeDB mirror failed (RuntimeError)"
    assert secret not in message
    assert len(message) <= mirror_packages._MIRROR_ERROR_MAX


def test_mirror_state_update_is_advisory_and_timestamped() -> None:
    source = mirror_packages._set_mirror_state.__doc__ or ""
    assert "activation state" in source
    implementation = inspect.getsource(mirror_packages._set_mirror_state)
    assert "mirror_status = $1" in implementation
    assert "mirror_updated_at = now()" in implementation


def test_package_template_binding_uses_versioned_probe_local_id() -> None:
    capacity = mirror_packages._binding_id(
        "KPK-case-1", "k8s_troubleshooting:scheduling_capacity:p01"
    )
    quota = mirror_packages._binding_id(
        "KPK-case-1", "k8s_troubleshooting:scheduling_quota:p01"
    )

    assert capacity == "KPK-case-1:v1:scheduling_capacity:p01"
    assert quota == "KPK-case-1:v1:scheduling_quota:p01"
    assert capacity != quota


def test_package_bindings_use_only_compiled_template_identifiers() -> None:
    payload = {
        "compiled": {
            "probe_template_ids": {
                "scheduling_quota": ["k8s_troubleshooting:scheduling_quota:p01"],
                "scheduling_capacity": [
                    "k8s_troubleshooting:scheduling_capacity:p01",
                    "k8s_troubleshooting:scheduling_capacity:p01",
                ],
            }
        }
    }
    assert mirror_packages._compiled_template_ids(payload) == [
        "k8s_troubleshooting:scheduling_capacity:p01",
        "k8s_troubleshooting:scheduling_quota:p01",
    ]
    assert mirror_packages._compiled_template_ids({"compiled": {"probe_template_ids": []}}) == []
    assert mirror_packages._compiled_template_ids(
        {"compiled": {"probe_template_ids": {"scheduling_capacity": "not-a-list"}}}
    ) == []
    assert mirror_packages._compiled_template_ids(
        {"compiled": {"probe_template_ids": {"scheduling_capacity": [123]}}}
    ) == []
