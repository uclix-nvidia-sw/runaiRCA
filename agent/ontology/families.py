"""The family whitelist the ontology loaders accept at ingest.

Must match the root_cause subtypes in schema.tql. Derived from the ranker's own
closed vocabulary rather than written out again, because writing it out again is
what broke: on 2026-07-31 load_alerts.py's copy had frozen at a stale subset of
5 and silently dropped 2 of 13 built-in alerts ("NVIDIA Run:ai Container Memory
Usage Critical/Warning", family workload_runtime_error) before they ever became
symptoms. Two hand-maintained copies of a closed vocabulary drift; one derived
set cannot.

``insufficient_evidence`` is the ranker's "no cause cleared the bar" sentinel —
an output, not a families.yaml rule — so both loaders have always special-cased
it in, and that stays explicit here.
"""

from __future__ import annotations

import os

from app.knowledge import load_family_catalog
from app.services.root_cause_ranking import INSUFFICIENT


def ingestable_families() -> frozenset[str]:
    """Every family an ontology loader may write, read from families.yaml.

    A families.yaml that fails to parse degrades to the built-in catalog, which
    is the same set the loaders used to hardcode — never to an empty whitelist
    that would drop every entry.
    """
    catalog = load_family_catalog(os.getenv("FAMILIES_FILE", "knowledge/families.yaml"))
    return frozenset(catalog.families) | {INSUFFICIENT}
