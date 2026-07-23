"""De-identify external support-case payloads before they enter this public repo.

The curated v2.0 payloads arrive carrying the real support-case number in several
fields. This script strips every trace of it and writes committable copies, so
the repo keeps the technical lesson without a traceable support-case record —
matching the existing knowledge/runai_known_issues.yaml practice (which likewise
publishes patterns, not case numbers).

What it removes / rewrites (the number and its disguises):
  - identity.source_case_number            -> dropped
  - identity.source_manifest               -> dropped (filenames embed the number)
  - ingestion_controls                     -> dropped (adapter prose repeats the key)
  - identity.deduplication_key             -> enterprise_support:<sha256(orig)[:12]>
  - identity.source_system                 -> "enterprise_support" (vendor removed)
  - incident.occurred_at                   -> date only (time + timezone dropped)
Everything the loader consumes (incident, searchable_context, evidence_refs,
historical_actions, historical_use, knowledge_links, source_revision_hash) is kept.
The output filename/dir is keyed by the opaque hash, never the number.

A hard assertion refuses to write any file in which the original number or key
still appears, so a leak fails loudly instead of being committed.

    python sanitize.py <raw_bundles_dir> [--out agent/knowledge/external_cases]

`<raw_bundles_dir>` is scanned recursively for 03_ingestion_payload.yaml; it lives
OUTSIDE this repo (the raw, numbered bundles are never committed).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

import yaml

PAYLOAD_NAME = "03_ingestion_payload.yaml"
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")

# Curated signature tokens for cases whose payloads carry NO error_signatures
# (observability / config-behavior incidents have no error string). Hand-picked
# signature-like tokens from each payload's retrieval_keywords; generic tokens
# (NFS, PVC, "above 100 percent") are deliberately excluded. Keyed by the opaque
# case hash — never by a support-case number.
_CURATED_TOKENS = {
    # GPU utilization >100% in native Analytics (observability_accuracy)
    "1f328ed5fa18": ["DCGM_FI_DEV_GPU_UTIL", "RUN-39130", "clamp_max"],
    # all-blocked storage policy shows every storage option (runai_control_plane_error)
    "4f211c4d1ebb": ["canAdd false", "2.23.71 fix", "Run:ai 2.23.x"],
    # existing-PVC-only storage policy: new PVC blocked, existing allowed
    # (runai_control_plane_error)
    "4b088e60d163": ["storage.pvc.instances canAdd false", "existingPvc true",
                     "claimName in policy defaults"],
    # negative CPU utilization from duplicate node-exporter scrape (observability_accuracy)
    "83292dbb5fe3": ["negative CPU compute utilization", "duplicate node-exporter scrape",
                     "ServiceMonitor PodMonitor duplicate collection"],
    # fractional GPU metrics missing under CDI/device-plugin rename (observability_accuracy)
    "f8cc6eda604d": ["runai_pod_gpu_info", "runai_gpu_utilization_per_fractional_pod",
                     "k8s.device-plugin.nvidia.com/gpu="],
}

# Cases whose curation_decision was needs_human_review, resolved by an explicit
# human semantic-diff review against the known-issues catalog (2026-07-16, owner).
# sanitize rewrites the decision with this audit trail so the loader's
# approved_for_ingestion gate stays intact (no loader change, no weakened gate).
_HUMAN_REVIEWED = {
    "0f59cfd7d537": "semantic_diff_review vs 'Scheduler Reclaim Panic On Large GPU Job': "
    "entry corrected (fix line 2.22.50, getVictimResources panic signature); "
    "case kept as unresolved prior",
    "239ee9638d98": "semantic_diff_review vs 'Distributed Training Locked hostPath Policy "
    "Rejected In UI': entry enriched (2.23.39 claimed fix ineffective, API workaround); "
    "case kept as resolved prior",
}


def _opaque_key(original_key: str) -> tuple[str, str]:
    """Return (new_deduplication_key, hash12) for a stable, one-way opaque id."""
    hash12 = hashlib.sha256(original_key.encode("utf-8")).hexdigest()[:12]
    return f"enterprise_support:{hash12}", hash12


def _date_only(value: object) -> object:
    if not isinstance(value, str):
        return value  # null / already absent
    m = _DATE_RE.match(value.strip())
    return m.group(1) if m else value


def sanitize(payload: dict) -> tuple[dict, str, list[str]]:
    """Return (sanitized_payload, hash12, secrets_to_verify_absent)."""
    identity = payload.get("identity") or {}
    original_key = str(identity.get("deduplication_key") or "")
    number = original_key.rsplit(":", 1)[-1].strip()
    new_key, hash12 = _opaque_key(original_key)

    identity["deduplication_key"] = new_key
    identity["source_system"] = "enterprise_support"
    identity.pop("source_case_number", None)
    identity.pop("source_manifest", None)
    payload["identity"] = identity
    payload.pop("ingestion_controls", None)

    incident = payload.get("incident")
    if isinstance(incident, dict) and "occurred_at" in incident:
        incident["occurred_at"] = _date_only(incident.get("occurred_at"))

    context = payload.get("searchable_context")
    if isinstance(context, dict) and hash12 in _CURATED_TOKENS:
        context["curated_signature_tokens"] = list(_CURATED_TOKENS[hash12])

    if hash12 in _HUMAN_REVIEWED:
        approval = payload.get("approval") or {}
        approval["curation_decision"] = "approved_for_ingestion_after_human_review"
        approval["human_review"] = _HUMAN_REVIEWED[hash12]
        payload["approval"] = approval

    # Values that must not survive anywhere in the output text.
    secrets = [s for s in {original_key, number} if s]
    return payload, hash12, secrets


def main() -> int:
    parser = argparse.ArgumentParser(description="De-identify external support-case payloads.")
    parser.add_argument("raw_dir", help="dir (outside the repo) holding raw numbered bundles")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent),
        help="output dir (default: this external_cases directory)",
    )
    args = parser.parse_args()

    out_root = Path(args.out)
    raw_files = sorted(Path(args.raw_dir).rglob(PAYLOAD_NAME))
    if not raw_files:
        print(f"no {PAYLOAD_NAME} found under {args.raw_dir}", file=sys.stderr)
        return 1

    written = 0
    for raw in raw_files:
        payload = yaml.safe_load(raw.read_text(encoding="utf-8")) or {}
        payload, hash12, secrets = sanitize(payload)
        text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        for secret in secrets:
            if secret in text:
                print(f"REFUSING to write {hash12}: '{secret}' still present", file=sys.stderr)
                return 2
        dest = out_root / f"case-{hash12}" / PAYLOAD_NAME
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        print(f"  {raw.parent.name} -> case-{hash12}/")
        written += 1
    print(f"sanitized {written} payload(s) into {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
