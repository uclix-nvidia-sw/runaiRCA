# Learning and Ontology, in Plain Language

> **In plain language:** learning is the team's reviewed casebook. Like a
> flight recorder plus a senior engineer's notebook, it remembers what happened
> only after a human says the lesson is trustworthy.

Run:AI RCA separates a current diagnosis from reusable knowledge. A diagnosis is
one claim about one incident. Evidence is the live observation that supports or
refutes that claim. A similar old incident can suggest a question, but it cannot
prove today's cause.

| Term | Plain meaning | Example |
| --- | --- | --- |
| Incident | A real operational event | A training job loses its GPU |
| Diagnosis | A claim about that event | “The GPU/driver path may have failed” |
| Probe | One bounded, read-only check | Read node journal lines |
| Evidence card | What a probe actually observed | Timestamped `Xid 79` line |
| Ontology | A map of things and their relationships | GPU Operator → driver daemonset |

## 1. The learning flow and its approval gate

```mermaid
flowchart LR
  A[Alert] --> P[Plan and read-only probes]
  P --> E[Evidence cards + trace-v3 receipt]
  E --> R[Current RCA]
  R --> O{Operator approves?}
  O -->|No| X[Keep for this incident only\nnot a prior]
  O -->|Yes| C[Approved CaseSnapshot]
  C --> M[Similar-incident memory]
  C --> T[(Optional TypeDB)]
  T --> Q[Future analysis gets labelled context]
```

| Gate | Why it exists | Result |
| --- | --- | --- |
| Operator approval | Stops guesses from teaching the system | Unapproved runs never become priors |
| Resolved/grace eligibility for ingest | Lets feedback and re-analysis settle | Stable approved cases enter TypeDB |
| Masked projection | Avoids copying raw sensitive material | Summary and evidence references, not logs/secrets |

This is not automatic self-training. Only `user_approved_at` cases are matched
as similar-incident memory and ingested into TypeDB. An approved unresolved RCA
may be retained as unresolved context, but it is not promoted as positive causal
knowledge. Re-analysis updates the same run's graph edges so stale evidence does
not linger.

## 2. What an ontology adds

```mermaid
flowchart TB
  subgraph Live[Live, incident-specific facts]
    L[Collectors] --> E[Evidence cards]
    E --> D[Diagnosis]
  end
  subgraph Knowledge[Reusable, optional context]
    T[Topology] --> C[Component dependency path]
    H[Approved history] --> S[Similar case context]
    K[Curated signatures] --> G[Checks and disconfirmations]
  end
  C --> P[Planner]
  S --> P
  G --> P
  P --> L
  D --> V[Verdict grounded in live evidence]
```

| Knowledge layer | Question it can answer | What it cannot do |
| --- | --- | --- |
| Curated signature | “What does Xid 79 usually warrant checking?” | Declare today’s GPU failed |
| Component topology | “What should be checked before/after this service?” | Invent a component outage |
| Approved history | “Has a reviewed similar case existed?” | Supply a high-confidence proof |

TypeDB is optional enrichment. If it is disabled or unavailable, file-based
catalogs still guide the planner and collectors still produce an RCA. The report
records the gap rather than silently claiming graph reasoning happened.

## 3. How guidance becomes safe investigation

```mermaid
sequenceDiagram
  participant A as Alert scope
  participant K as Knowledge card / graph
  participant P as Planner
  participant G as Evidence agent
  participant B as Evidence blackboard
  A->>K: match text or component identity
  K->>P: questions, checks, disconfirmations, probe templates
  P->>G: source-scoped diagnostic directive
  G->>G: use only its registered read-only tools
  G->>B: evidence card with time and source
  B->>P: support/refute view
```

The diagnostic directive is deliberately declarative. It can say “inspect the
driver daemonset for this alert's node,” but it is never an executable command.
Only placeholders already present in the alert scope can be resolved. Kubernetes,
Loki, Prometheus, Run:ai, and Postgres agents each retain their own tool registry,
which is the actual permission boundary.

`trace-v3` is the investigation receipt. It records the hypothesis, probe,
time relation, source group, and whether an observation supported or refuted a
claim. It prevents later corroboration from being presented as if it was known
at alert time.

## 4. Worked example: Xid 79 from alert to verdict

1. An alert or Loki/System line says `NVRM: Xid ... 79` and “GPU has fallen off
   the bus.” The curated XID card matches before any family ranker decision.
2. The card identifies the GPU-hardware path and gives questions such as “is the
   driver reporting a persistent device loss?” plus disconfirmations such as a
   clean driver journal.
3. The planner gives relevant agents declarative, read-only probes. A component
   name such as `nvidia-driver-daemonset-...` can reach the same topology path
   even without the XID text.
4. The operator sees evidence cards: a timestamped Xid line, affected node,
   collection gaps, and the exact evidence IDs used by the RCA.
5. If independent live signals agree, the verdict can cite them. If they do not,
   the report says `insufficient_evidence` and retains the card as a next-check
   guide rather than claiming a hardware fault.

## 5. In depth: packages and the graph mirror

Backend Postgres is the authority for package approval, activation, and
retirement. A `shadow` package is observed but not active; `activate` explicitly
enables it; `approve` validates and activates it; `reject`/`retired` keep it out
of runtime use. The TypeDB package-mirror CronJob copies summaries and approved
template bindings for graph queries; it never changes activation.

How active and shadow packages actually feed a live analysis is governed by the
runtime activation ladder (`DYNAMIC_KNOWLEDGE_MODE`: off/shadow/assist/
authoritative) — see [Knowledge Base](KNOWLEDGE-BASE.md#3-how-knowledge-is-used-during-an-analysis).

Candidate compilation prefers the complete trace-v3 ledger path. A supported
harness claim can provide a second promotion path when the ledger is incomplete,
but only when its family matches the approved snapshot and its supporting
evidence is canonical, non-contradictory, and non-empty. The harness-claim path
does not require two source groups or a linked probe execution, does not invent
probe IDs, and is marked with `evidence_source: "harness_claim"` for audit.
Evaluation re-save revalidates the exact run/hash and refreshes the latest failure
reason when the candidate remains ineligible.

## 6. External support-case priors

Some lessons come from outside our own clusters — curated enterprise support
cases. They arrive as masked v2.0 payloads and are treated as **external
reference cases, never proof**:

- **De-identified before commit.** Raw bundles carry a real support-case number;
  `agent/knowledge/external_cases/sanitize.py` strips it everywhere (identity,
  manifest filenames, prose), replaces the case key with an opaque hash, and
  coarsens timestamps to dates. Only the de-identified copies are committed —
  the same publish-the-lesson-not-the-record practice as the known-issues
  catalog. The sanitizer refuses to emit a file that still contains the number.
- **Approval is explicit.** The Helm schema-load job runs the loader only with an
  operator-set approver (`typedb.externalCases.approvedBy`), recorded on every
  case — the same approval gate as section 1.
- **Never knowledge-layer authority.** They enter TypeDB as labelled case
  snapshots with a case-local symptom, but the loader structurally never writes
  the `indicates`/`resolved_by` edges the knowledge layer requires, so they can
  never become a catalog rule that names a cause.
- **Retrieved by error signature.** A future analysis surfaces one only when an
  error signature (e.g. `ibv_modify_qp failed with 19 No such device`) actually
  appears in that run's observed evidence. It then appears as historical context,
  labelled with its use-class (`evaluation_only`, `mitigated_context`,
  `unresolved_context`). Actions it tried — including the ones that did **not**
  work — are shown as "attempted in a past external case," never as a verified
  fix for the current incident.

For the de-identification contract and how to add a case, see
`agent/knowledge/external_cases/README.md`.

For the catalog map, see [Knowledge Base](KNOWLEDGE-BASE.md). For entities,
relations, and safe TypeDB Studio checks, see [Ontology Guide](ONTOLOGY-GUIDE.md).
