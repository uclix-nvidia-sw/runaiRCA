from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from re import Pattern
from typing import Any, Protocol, runtime_checkable

MASK_TOKEN = "[MASKED]"

_DENIED_KEY_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "credential",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "access_key",
    "client_secret",
)

_ALLOWED_KEYS = {
    "secret_name",
    "secret_ref",
    "secret_key_ref",
    "token_budget",
    "token_path",
    "kubernetes_token_path",
}

_HEURISTIC_SKIP_KEYS = {
    "containerid",
    "generation",
    "image",
    "imageid",
    "resourceversion",
    "selflink",
    "uid",
}

_TEXT_PATTERNS: tuple[Pattern[str], ...] = (
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"\b(?:Basic|Bearer|Digest|Token)\s+[A-Za-z0-9+/=_.~-]{8,}"),
    re.compile(
        r"(?i)(postgres(?:ql)?://[^:\s/@]+:)([^@\s]+)(@)"
    ),
    re.compile(
        r"(?i)([?&](?:access_token|api_key|apikey|key|token)=)([^\s&]+)"
    ),
    re.compile(
        r"(?i)([\"']?(?:access[_-]?key|api[_-]?key|client[_-]?secret|"
        r"credential|password|secret|[a-z0-9_-]*token)[\"']?\s*:\s*[\"']?)"
        r"([^\"',\s}{]+)([\"']?)"
    ),
    re.compile(
        r"(?i)\b((?:access[_-]?key|api[_-]?key|client[_-]?secret|"
        r"credential|password|secret|[a-z0-9_-]*token)\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(
        r"(?i)(--(?:access[_-]?key|api[_-]?key|client[_-]?secret|"
        r"credential|password|secret|[a-z0-9_-]*token)=)(\S+)"
    ),
)
_LONG_BASE64_RE = re.compile(
    r"(?<!sha256:)(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/])"
)


@runtime_checkable
class Masker(Protocol):
    def mask_object(self, value: Any) -> Any: ...
    def mask_text(self, text: str) -> str: ...


@dataclass(frozen=True)
class RedactingMasker:
    regex_patterns: tuple[Pattern[str], ...] = ()
    builtin_enabled: bool = True
    hash_mode: bool = False

    @classmethod
    def from_patterns(
        cls,
        patterns: tuple[str, ...] | list[str],
        *,
        builtin_enabled: bool = True,
        hash_mode: bool = False,
    ) -> RedactingMasker:
        compiled = tuple(re.compile(pattern) for pattern in patterns)
        return cls(
            regex_patterns=compiled,
            builtin_enabled=builtin_enabled,
            hash_mode=hash_mode,
        )

    def mask_text(self, text: str) -> str:
        if not text:
            return text
        masked = self._redact_text(text, parent_key="")
        for pattern in self.regex_patterns:
            masked = pattern.sub(MASK_TOKEN, masked)
        return masked

    def mask_object(self, value: Any) -> Any:
        masked = self._redact_value(value, parent_key="")
        return self._apply_regex_to_object(masked)

    def _replacement(self, original: str) -> str:
        if not self.hash_mode:
            return MASK_TOKEN
        digest = hashlib.sha256(original.encode("utf-8", errors="replace")).hexdigest()[:8]
        return f"[HASH:{digest}]"

    def _redact_text(self, text: str, *, parent_key: str) -> str:
        if not self.builtin_enabled or len(text) < 8:
            return text
        if _normalize_key(parent_key) in _HEURISTIC_SKIP_KEYS:
            return text

        masked = text
        for index, pattern in enumerate(_TEXT_PATTERNS):
            def replacement(match):  # noqa: ANN001
                value = match.group(2) if pattern.groups >= 2 else match.group(0)
                if index in {4, 5} and not _looks_like_credential(value):
                    return match.group(0)
                if pattern.groups >= 3:
                    return f"{match.group(1)}{self._replacement(match.group(2))}{match.group(3)}"
                if pattern.groups >= 2:
                    return f"{match.group(1)}{self._replacement(match.group(2))}"
                return self._replacement(match.group(0))
            masked = pattern.sub(replacement, masked)
        return _LONG_BASE64_RE.sub(
            lambda match: self._replacement(match.group(0))
            if _is_valid_base64(match.group(0))
            else match.group(0),
            masked,
        )
    def _redact_value(self, value: Any, *, parent_key: str) -> Any:
        if isinstance(value, str):
            return self._redact_text(value, parent_key=parent_key)
        if isinstance(value, list):
            normalized_key = _normalize_key(parent_key)
            if normalized_key in {"env", "envfrom"}:
                return [self._redact_env_item(item) for item in value]
            if normalized_key in {"args", "command"}:
                return [self._redact_command_item(item) for item in value]
            return [self._redact_value(item, parent_key=parent_key) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact_value(item, parent_key=parent_key) for item in value)
        if isinstance(value, dict):
            return self._redact_dict(value)
        return value

    def _redact_dict(self, value: dict[Any, Any]) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            normalized_key = _normalize_key(key_text)
            if normalized_key == "annotations" and isinstance(child, dict):
                out[key] = self._redact_annotations(child)
            elif self._is_sensitive_key(normalized_key):
                out[key] = self._mask_sensitive_value(child)
            else:
                out[key] = self._redact_value(child, parent_key=key_text)
        return out

    def _redact_annotations(self, annotations: dict[Any, Any]) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        for key, value in annotations.items():
            if not isinstance(value, str):
                out[key] = value
                continue
            key_text = str(key)
            normalized_key = _normalize_key(key_text)
            if self._is_sensitive_key(normalized_key):
                out[key] = self._replacement(value)
            else:
                out[key] = self._redact_text(value, parent_key=key_text)
        return out

    def _redact_env_item(self, item: Any) -> Any:
        if not isinstance(item, dict):
            return self._redact_value(item, parent_key="env")
        out = dict(item)
        if isinstance(out.get("value"), str):
            out["value"] = self._replacement(out["value"])
        return self._redact_dict(out)

    def _redact_command_item(self, item: Any) -> Any:
        if isinstance(item, str):
            return self._redact_text(item, parent_key="args")
        return self._redact_value(item, parent_key="args")

    def _mask_sensitive_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._replacement(value)
        if isinstance(value, (int, float, bool)):
            return self._replacement(str(value))
        if isinstance(value, list):
            return [self._mask_sensitive_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._mask_sensitive_value(item) for item in value)
        if isinstance(value, dict):
            return {key: self._mask_sensitive_value(item) for key, item in value.items()}
        return value

    def _is_sensitive_key(self, normalized_key: str) -> bool:
        if not self.builtin_enabled or normalized_key in _ALLOWED_KEYS:
            return False
        return any(part in normalized_key for part in _DENIED_KEY_PARTS)


    def _apply_regex_to_object(self, value: Any) -> Any:
        if isinstance(value, str):
            masked = value
            for pattern in self.regex_patterns:
                masked = pattern.sub(MASK_TOKEN, masked)
            return masked
        if isinstance(value, list):
            return [self._apply_regex_to_object(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._apply_regex_to_object(item) for item in value)
        if isinstance(value, dict):
            return {key: self._apply_regex_to_object(item) for key, item in value.items()}
        return value


def _looks_like_credential(value: str) -> bool:
    return (
        any(char.isdigit() for char in value)
        or (any(char.islower() for char in value) and any(char.isupper() for char in value))
        or len(value) >= 16
        or any(not char.isalnum() for char in value)
    )


def build_masker(
    patterns: tuple[str, ...] | list[str],
    *,
    builtin_enabled: bool = True,
    hash_mode: bool = False,
) -> RedactingMasker:
    return RedactingMasker.from_patterns(
        patterns,
        builtin_enabled=builtin_enabled,
        hash_mode=hash_mode,
    )


def _normalize_key(key: str) -> str:
    return key.lower().replace("-", "_")


def _is_valid_base64(text: str) -> bool:
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception:
        return False
    return len(decoded) >= 16
