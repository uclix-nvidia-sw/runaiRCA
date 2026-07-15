from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import quote

from app.collectors.http_json import post_json
from app.config import Settings
from app.masking import Masker, RedactingMasker

_RUN_ID_RE = re.compile(r"^ANL-[A-Za-z0-9._-]{1,128}$")


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
        # Progress used to be dispatched as unrelated fire-and-forget tasks.
        # The backend can mark a run terminal as soon as the agent response
        # arrives, so synthesis/harness updates racing behind that response were
        # rejected with HTTP 409.  Chaining the sends keeps their order stable;
        # ``flush`` below lets the pipeline drain the final update before return.
        self._send_tail: asyncio.Task[None] | None = None
        self._last_ledger_fingerprint: str | None = None

    @classmethod
    def from_alert(
        cls, settings: Settings, alert: object, masker: Masker | None = None
    ) -> ProgressReporter:
        annotations = getattr(alert, "annotations", None) or {}
        return cls(settings, str(annotations.get("analysis_run_id") or ""), masker)

    @property
    def enabled(self) -> bool:
        return bool(self._backend_url and _RUN_ID_RE.fullmatch(self._run_id))

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
            if not isinstance(masked, dict):
                return
            ledger = masked.get("hypothesis_ledger")
            if ledger is not None:
                fingerprint = json.dumps(
                    ledger,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
                if fingerprint == self._last_ledger_fingerprint:
                    # The timeline scans backwards for the latest event that
                    # contains a ledger, so unchanged snapshots need not be
                    # copied into every exchange payload.
                    masked = dict(masked)
                    masked.pop("hypothesis_ledger", None)
                else:
                    self._last_ledger_fingerprint = fingerprint
            previous = self._send_tail
            self._send_tail = asyncio.create_task(self._post_after(previous, masked))
        except Exception:  # noqa: BLE001 - progress must never affect analysis
            return

    async def flush(self, timeout_seconds: float = 4.0) -> None:
        """Best-effort drain of progress emitted immediately before completion."""
        tail = self._send_tail
        if tail is None:
            return
        try:
            await asyncio.wait_for(asyncio.shield(tail), timeout=max(0.0, timeout_seconds))
        except TimeoutError:
            # Telemetry must never hold the RCA response hostage when the
            # backend is unavailable. The already-running task remains shielded
            # and may still complete while the process stays alive.
            return
        finally:
            if self._send_tail is tail and tail.done():
                self._send_tail = None

    async def _post_after(
        self,
        previous: asyncio.Task[None] | None,
        payload: dict[str, Any],
    ) -> None:
        if previous is not None:
            try:
                await previous
            except Exception:  # noqa: BLE001 - a prior telemetry failure is isolated
                pass
        await self._post(payload)

    async def _post(self, payload: dict[str, Any]) -> None:
        try:
            await post_json(
                url=(
                    f"{self._backend_url}/api/v1/analysis-runs/"
                    f"{quote(self._run_id, safe='')}/progress"
                ),
                timeout_seconds=3,
                json_body=payload,
            )
        except Exception:  # noqa: BLE001 - fire-and-forget telemetry
            return
