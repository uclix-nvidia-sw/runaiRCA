"""XID causal drill-down rendering + the 'timeout 0 = unlimited' convention."""

from __future__ import annotations

from app.collectors.http_json import _client_timeout
from app.schemas import Alert, AlertAnalysisRequest
from app.services.kg_enrichment import GraphRemediation
from app.services.pipeline import _causal_chain_line, _numbered_actions
from app.services.root_cause_ranking import RankedCause


def test_client_timeout_zero_is_unlimited() -> None:
    assert _client_timeout(0) is None      # 0 -> no timeout (let it think)
    assert _client_timeout(-1) is None
    assert _client_timeout(6) == 6         # positive keeps the bound


def test_graph_remediation_tracks_root_xids() -> None:
    gr = GraphRemediation(xid_fixes={45: ["restart app"]}, root_xids={45: [74]})
    assert not gr.is_empty()
    assert gr.as_dict()["root_xids"] == {"45": [74]}


def test_causal_chain_line_names_root_to_observed() -> None:
    gr = GraphRemediation(xid_fixes={45: ["fix"], 74: ["reset nvlink"]}, root_xids={45: [74]})
    line = _causal_chain_line(gr, "en")
    assert "XID 74 → XID 45" in line
    assert "root" in line.lower()
    ko = _causal_chain_line(gr, "ko")
    assert "XID 74 → XID 45" in ko and "뿌리" in ko


def test_causal_chain_line_without_roots_is_plain() -> None:
    gr = GraphRemediation(xid_fixes={31: ["fix"]})
    line = _causal_chain_line(gr, "en")
    assert "XID" in line and "→" not in line


def test_causal_chain_line_empty_when_no_xid() -> None:
    assert _causal_chain_line(GraphRemediation(), "en") == ""
    assert _causal_chain_line(None, "en") == ""


def test_root_xid_fix_is_ordered_first() -> None:
    # Drill-down precision: the ROOT of the causal chain (74) is fixed before its
    # downstream symptom (45), and labelled as the root.
    gr = GraphRemediation(
        xid_fixes={
            45: ["patch the app password=xid-action-secret-12345"],
            74: ["reset the NVLink fabric\n## injected"],
        },
        root_xids={45: [74]},
    )
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "X"}, annotations={}, fingerprint="fp")
    )
    actions = _numbered_actions(
        None,
        gr,
        [RankedCause(family="gpu_hardware_error", confidence="low", score=1.0)],
        "",
        {},
        [],
        request,
    )
    joined = "\n".join(actions)
    assert "root XID 74" in joined
    assert joined.index("root XID 74") < joined.index("XID 45")
    assert "xid-action-secret-12345" not in joined
    assert "\n## injected" not in joined
    assert "[MASKED]" in joined
