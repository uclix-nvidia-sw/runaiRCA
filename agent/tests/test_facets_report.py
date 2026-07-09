from __future__ import annotations

from app.services.pipeline import _facets_line
from app.services.root_cause_ranking import RankedCause


def test_facets_line_renders_locus_nature_trigger_en() -> None:
    top = RankedCause(
        family="platform_lifecycle_change",
        confidence="high",
        score=8.0,
        trigger="rollout/upgrade on gpu-operator; Helm: gpu-operator rev 3 (pending-upgrade)",
    )
    line = _facets_line(top, "en")
    assert line.startswith("- Facets:")
    assert "Subsystem: platform-lifecycle" in line
    assert "lifecycle change" in line
    assert "Trigger:" in line and "gpu-operator" in line


def test_facets_line_korean_labels() -> None:
    top = RankedCause(family="gpu_hardware_error", confidence="high", score=6.0)
    line = _facets_line(top, "ko")
    assert "서브시스템: gpu" in line
    assert "성격" in line and "결함" in line
    # No trigger known -> the Trigger axis is omitted, not blank.
    assert "트리거" not in line


def test_facets_line_empty_for_insufficient_evidence() -> None:
    top = RankedCause(family="insufficient_evidence", confidence="low", score=0.0)
    assert _facets_line(top, "en") == ""


def test_facets_line_auto_derives_from_family() -> None:
    # subsystem/nature are auto-filled by RankedCause.__post_init__ from the family.
    top = RankedCause(family="node_kubelet_pressure", confidence="high", score=5.0)
    assert top.subsystem == "node"
    assert top.nature == "saturation"
    line = _facets_line(top, "en")
    assert "Subsystem: node" in line
    assert "saturation" in line
