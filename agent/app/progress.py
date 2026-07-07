from __future__ import annotations

import asyncio
from typing import Any

from app.collectors.http_json import post_json
from app.config import Settings
from app.masking import Masker, RedactingMasker


class ProgressReporter:
    def __init__(self, settings: Settings, run_id: str, masker: Masker | None = None) -> None:
        self._settings = settings
        self._run_id = (run_id or "").strip()
        self._backend_url = (settings.backend_url or "").strip().rstrip("/")
        self._masker = masker or RedactingMasker.from_patterns(
            settings.masking_regex_list,
            builtin_enabled=settings.builtin_redaction_enabled,
            hash_mode=settings.builtin_redaction_hash_mode,
        )

    @classmethod
    def from_alert(
        cls, settings: Settings, alert: object, masker: Masker | None = None
    ) -> ProgressReporter:
        annotations = getattr(alert, "annotations", None) or {}
        return cls(settings, str(annotations.get("analysis_run_id") or ""), masker)

    @property
    def enabled(self) -> bool:
        return bool(self._backend_url and self._run_id)

    def emit(self, phase: str, message: str, **fields: Any) -> None:
        if not self.enabled:
            return
        payload = {
            "phase": phase,
            "message": message,
            **{key: value for key, value in fields.items() if value is not None},
        }
        try:
            masked = self._masker.mask_object(payload)
            asyncio.create_task(self._post(masked if isinstance(masked, dict) else payload))
        except Exception:  # noqa: BLE001 - progress must never affect analysis
            return

    async def _post(self, payload: dict[str, Any]) -> None:
        try:
            await post_json(
                url=f"{self._backend_url}/api/v1/analysis-runs/{self._run_id}/progress",
                timeout_seconds=3,
                json_body=payload,
            )
        except Exception:  # noqa: BLE001 - fire-and-forget telemetry
            return
