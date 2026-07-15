from dataclasses import replace

from app.collectors.registry import collector_names, unknown_collector_names
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from tests.test_orchestrator import make_settings


def test_unknown_collector_is_reported_in_health_and_aggregated_warnings(monkeypatch) -> None:
    settings = replace(make_settings(), collectors=("runai", "prometheuz"))
    assert collector_names(settings) == ["runai"]
    assert unknown_collector_names(settings) == ["prometheuz"]

    state = pipeline.new_state(
        settings,
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "test"})),
        collectors=[],
    )
    pipeline._aggregate_evidence(state)
    assert state.warnings == [
        "configured collector 'prometheuz' is unknown; its evidence plane is missing"
    ]

    from app import main

    monkeypatch.setattr(main, "settings", settings)
    assert main.healthz()["collectors"] == {
        "active": ["runai"],
        "unknown": ["prometheuz"],
    }
