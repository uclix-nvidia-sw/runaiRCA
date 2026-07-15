from __future__ import annotations

import json
from typing import Any

from app.schemas import AlertAnalysisResponse

_ARTIFACT_PREVIEW_BYTES = 4096
_PROTECTED_CONTEXT_KEYS = frozenset(
    {
        "analysis_hash",
        "harness",
        "llm_usage",
        "response_budget",
        "root_cause_candidates",
        "target",
        "top_root_cause",
    }
)


def analysis_response_bytes(response: AlertAnalysisResponse) -> int:
    return len(response.model_dump_json().encode("utf-8"))


def enforce_analysis_response_budget(
    response: AlertAnalysisResponse,
    max_bytes: int,
    *,
    language: str = "en",
) -> bool:
    """Fit an analysis response under its transport budget.

    The operator-facing summary/detail and evidence-card summaries are retained
    ahead of raw collector payloads and internal reasoning traces. Small responses
    are returned byte-for-byte unchanged.
    """
    original_bytes = analysis_response_bytes(response)
    if max_bytes <= 0 or original_bytes <= max_bytes:
        return False

    if not isinstance(response.context, dict):
        response.context = {}
    metadata: dict[str, Any] = {
        "applied": True,
        "final_bytes": 0,
        "max_bytes": max_bytes,
        "original_bytes": original_bytes,
        "omitted_artifacts": 0,
        "omitted_context_keys": [],
        "truncated_artifact_results": 0,
    }
    response.context["response_budget"] = metadata
    warning = (
        "Agent 응답이 전송 크기 제한에 맞게 축약되었습니다. 보고서 본문은 보존하고 "
        "일부 원시 증거와 내부 추론 메타데이터를 생략했습니다."
        if language == "ko"
        else "The Agent response was compacted to fit the transport limit. The report "
        "was preserved while some raw evidence and internal reasoning metadata were omitted."
    )
    if warning not in response.warnings:
        response.warnings.append(warning)

    # analysis_detail is the canonical field used by the backend. ``analysis`` is
    # a compatibility fallback and normally contains the exact same report.
    if response.analysis == response.analysis_detail:
        response.analysis = ""

    _bound_artifact_labels(response)
    for _, artifact in sorted(
        (
            (_json_bytes(item.result), item)
            for item in response.artifacts
            if item.result is not None
        ),
        key=lambda pair: pair[0],
        reverse=True,
    ):
        if analysis_response_bytes(response) <= max_bytes:
            break
        original_result_bytes = _json_bytes(artifact.result)
        artifact.result = {
            "truncated": True,
            "original_bytes": original_result_bytes,
            "preview": _preview(artifact.result, _ARTIFACT_PREVIEW_BYTES),
        }
        metadata["truncated_artifact_results"] += 1

    removable_context = sorted(
        (
            (_json_bytes(value), key)
            for key, value in response.context.items()
            if key not in _PROTECTED_CONTEXT_KEYS
        ),
        reverse=True,
    )
    for _, key in removable_context:
        if analysis_response_bytes(response) <= max_bytes:
            break
        response.context.pop(key, None)
        metadata["omitted_context_keys"].append(key)

    # If previews plus evidence-card metadata are still too large, retain the
    # summary/highlights but drop result previews before dropping whole cards.
    for artifact in sorted(
        response.artifacts,
        key=lambda item: _json_bytes(item.model_dump(mode="json")),
        reverse=True,
    ):
        if analysis_response_bytes(response) <= max_bytes:
            break
        artifact.result = None

    while response.artifacts and analysis_response_bytes(response) > max_bytes:
        largest = max(
            range(len(response.artifacts)),
            key=lambda index: _json_bytes(response.artifacts[index].model_dump(mode="json")),
        )
        response.artifacts.pop(largest)
        metadata["omitted_artifacts"] += 1

    if analysis_response_bytes(response) > max_bytes:
        response.context = {
            key: value
            for key, value in response.context.items()
            if key in {"target", "top_root_cause", "llm_usage", "response_budget"}
        }

    # This is a last-resort guard for a pathological report body. Normal LLM and
    # deterministic reports are far smaller than half the response budget.
    if analysis_response_bytes(response) > max_bytes:
        response.analysis_detail = _truncate_utf8(
            response.analysis_detail,
            max(4096, max_bytes // 2),
        )
        response.analysis = ""
        response.analysis_summary = _truncate_utf8(response.analysis_summary, 4096)
        response.warnings = [_truncate_utf8(item, 1024) for item in response.warnings[:20]]
        response.missing_data = [_truncate_utf8(item, 512) for item in response.missing_data[:50]]

    # Account for JSON escaping by shaving only the report tail if an unusually
    # small configured budget is still exceeded after all diagnostic data is gone.
    while analysis_response_bytes(response) > max_bytes and len(response.analysis_detail) > 4096:
        excess = analysis_response_bytes(response) - max_bytes
        response.analysis_detail = _truncate_utf8(
            response.analysis_detail,
            max(4096, len(response.analysis_detail.encode("utf-8")) - excess - 256),
        )

    # Two assignments make the recorded number include the metadata field itself;
    # the second assignment does not change the JSON shape or digit width.
    metadata["final_bytes"] = analysis_response_bytes(response)
    metadata["final_bytes"] = analysis_response_bytes(response)
    return True


def _bound_artifact_labels(response: AlertAnalysisResponse) -> None:
    for artifact in response.artifacts:
        artifact.query = _truncate_utf8(artifact.query or "", 4096) or None
        artifact.summary = _truncate_utf8(artifact.summary or "", 4096) or None
        artifact.title = _truncate_utf8(artifact.title or "", 512) or None
        if artifact.highlights:
            artifact.highlights = [_truncate_utf8(item, 512) for item in artifact.highlights[:20]]


def _preview(value: Any, max_bytes: int) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            text = str(value)
    return _truncate_utf8(text, max_bytes)


def _json_bytes(value: Any) -> int:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = str(value).encode("utf-8", errors="replace")
    return len(encoded)


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    suffix = "..."
    body = encoded[: max(0, max_bytes - len(suffix))]
    return body.decode("utf-8", errors="ignore") + suffix
