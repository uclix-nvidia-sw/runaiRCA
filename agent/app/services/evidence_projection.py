"""Projection helpers that keep retrieval intent out of observed evidence."""

from __future__ import annotations

import re
from collections.abc import Iterable

EXECUTION_METADATA_KEYS = frozenset(
    {
        "args",
        "arguments",
        "command",
        "debug",
        "expr",
        "expression",
        "hints",
        "logql",
        "metadata",
        "path",
        "possiblecause",
        "possiblecauses",
        "promql",
        "queries",
        "query",
        "remediation",
        "remediationhint",
        "remediationhints",
        "remediations",
        "request",
        "requestbody",
        "sql",
        "suggestion",
        "suggestions",
        "title",
        "url",
    }
)

_OMIT = object()


def normalized_field_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def observed_payload(
    value: object, *, additional_drop_keys: Iterable[str] = ()
) -> object:
    """Return data values without query, request, debug, or suggestion fields.

    The original artifact remains untouched for the operator-facing UI. This
    projection is for LLM/ranking inputs where a submitted search term must
    never be indistinguishable from a value returned by the datasource.
    """

    drop_keys = EXECUTION_METADATA_KEYS | frozenset(
        normalized_field_name(key) for key in additional_drop_keys
    )

    def walk(node: object, key: object = "") -> object:
        if normalized_field_name(key) in drop_keys:
            return _OMIT
        if isinstance(node, dict):
            projected: dict[str, object] = {}
            for child_key, child in node.items():
                child_value = walk(child, child_key)
                if child_value is not _OMIT:
                    projected[str(child_key)] = child_value
            return projected
        if isinstance(node, (list, tuple)):
            projected_list = []
            for child in node:
                child_value = walk(child, key)
                if child_value is not _OMIT:
                    projected_list.append(child_value)
            return projected_list
        return node

    projected = walk(value)
    return {} if projected is _OMIT else projected
