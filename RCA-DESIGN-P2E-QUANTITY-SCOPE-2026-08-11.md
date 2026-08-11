# P2-E 설계안 — 수량형 무라벨 알림의 scope 자가 유도 (승인 대기)

작성: 2026-08-11 · 설계: Codex(세션 019fef2b-d9fe…) · 검토: Claude(코디네이터) · 상태: **설계 승인, 구현 보류 — 전제조건 1건**

## 검토 판정 (코디네이터)

- **원안 수정**: 필드 리뷰의 원제안(prometheus per-node GPU 메트릭의 시간축 diff)은 **기각이 옳다** — Codex가 고정 쿼리 계약(`prometheus.py:_queries_for`)과 드릴다운 known-series 허용목록을 전수 확인한 결과 per-node GPU 시리즈가 코드베이스에 존재하지 않는다. 존재하지 않는 메트릭을 발명하지 않는 것이 이 레포의 원칙이다.
- **채택안**: Run:ai `get_cluster_physical_inventory`의 노드별 `physical_total − allocatable` deficit이 **정확히 한 노드에서만 양수**일 때만 그 노드를 승격. allocated/free는 배치 노이즈라 선택 기준에서 배제한 것도 옳다.
- **정직성 검증 통과**: `target_identity_verified` 미날인, `declared_target` 불변, 유도 영수증은 scope seed(증거·랭킹 진입 금지), 증거 강등 규칙 무변경, resolved 알림 승격 금지, 리포트는 "derived, not alert-declared"로 명시 — seed-honesty 불변식 전 지점 보존.
- **전제조건(구현 착수 차단기)**: Run:ai MCP `get_cluster_physical_inventory`의 **노드별 실제 payload가 레포에 fixture로 없다**(현재 파싱되는 건 집계 `byGpuModel`뿐). 실 클러스터에서 응답 1건을 캡처해 fixture로 박은 뒤에만 파서를 구현한다 — 실측 없는 MCP 계약 커밋 금지 원칙. 캡처 전이면 Kubernetes Nodes 폴백(`nvidia.com/gpu` capacity/allocatable)만으로 1차 구현하는 축소안도 가능.
- **롤아웃**: 차트 플래그 기본 off → 리플레이/카나리 검증 후 on. 예상 규모 ~180–250 프로덕션 라인 + 150–220 테스트 라인, 6–8 파일.

## 실측 수정 (AMENDMENT, 2026-08-11 payload 캡처 후) — 유도 규칙 확정

운영 클러스터에서 두 MCP 응답을 캡처해 fixture로 커밋했다
(`agent/tests/fixtures/runai_mcp/cluster_physical_inventory.json`, `cluster_infrastructure_health.json`).
실측 결과가 아래 §3의 가정을 뒤집는다:

- **inventory에는 per-node 행이 존재하지 않는다** (`byGpuModel` 모델 합계, `byNodePool`/`totals` 집계뿐).
  설계의 1차 유도식(노드별 physical−allocatable)은 이 payload로 구현 불가 — 설계가 fail-closed로
  예고한 케이스가 실제로 확인됐다.
- **확정 유도 규칙 (교차 대조, 원안보다 강함)**:
  1. inventory `totals`: `deficit = gpusTotal − gpusAllocatable` (두 값 모두 유한 정수 ≥0,
     allocatable ≤ total). `deficit ≤ 0` → inconclusive.
  2. health `unhealthyNodes[]`: `gpus.count > 0`인 항목만 후보. **정확히 1개** 존재하고
     그 `gpus.count == deficit`일 때만 그 `name`을 승격. GPU 보유 unhealthy 노드가 2개 이상이면
     (합이 맞아떨어져도) inconclusive.
  3. Kubernetes Nodes 폴백(§3의 unique-positive-deficit 규칙)은 유지하되, inventory 결손값이
     확보된 상태에서 폴백 결과와 불일치하면 inconclusive.
- §3의 "health는 노드를 독립 선정할 수 없다" 규칙은 **완화가 아니라 대체**된다: health가 노드를
  지명하되 inventory의 수량 게이트와 정확 일치해야만 하므로, 두 독립 소스의 합치가 필수가 됐다.
- 실측 검증: 이 인시던트에서 `16 − 8 = 8` == dgx02(`gpus.count 8`, NotReady/SchedulingDisabled),
  유일 후보 → 정답 노드가 도출된다.
- 그 외 정직성 규칙(§4)·실패 봉쇄(§5)·엣지 케이스·테스트 계획은 원안 유지. 전제조건(fixture)은
  이 캡처로 해소되어 **구현 착수 가능** 상태다.

이하 Codex 설계 원문(영문, 무수정).

---

## Recommendation

Implement a conservative first version behind `ENABLE_QUANTITY_SCOPE_DERIVATION=false`.

The repository can safely derive a node today from a unique physical-GPU-versus-allocatable deficit. It cannot currently perform the originally suggested historical Prometheus comparison: there is no existing per-node GPU PromQL metric in the codebase. Do not invent one.

Promote only active/firing alerts when exactly one GPU node has a positive deficit. Record `node_source="derived_from_inventory_deficit"`, keep the alert-declared target immutable, and never insert the derivation receipt into causal evidence.

## 1. Detection

Alert metadata becomes an `AnalysisTarget` in [`base.py:resolve_target`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/base.py:644), called by [`pipeline.py:new_state`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:232). `value_from` prefers labels over annotations and rejects empty/template/control-character values at [`base.py:value_from`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/base.py:157).

Add `classify_scope_less_quantity_alert(labels, annotations, target)` beside `resolve_target` in `base.py`. It should return `"gpu"` or `""`:

- Require `target.node`, `target.pod`, and `target.namespace` all empty. This covers their label aliases and annotation fallbacks because `resolve_target` already reads `node|node_name|kubernetes_node`, `pod|pod_name|kubernetes_pod_name`, and `namespace|kubernetes_namespace`.
- Require at least one finite numeric value from the exact Grafana keys `__values__` or `__value_string__`.
- For `__value_string__`, parse only `value=<finite decimal>` fields; reject non-empty embedded `labels={...}`.
- For `__values__`, use `json.loads`, accept numeric `Value/value` leaves, and require any accompanying `Labels/labels` mapping to be empty.
- Reject booleans, NaN, infinities, arbitrary numbers in `summary`/`description`, and malformed JSON.
- Require a bounded GPU resource discriminator such as an exact `gpu|gpus` token in `alert_name`, title, or summary. Other quantity alerts classify as unsupported and remain unchanged.
- Do not interpret Grafana expression values as “before” and “after.” In this incident `C=1` may be a condition/threshold expression, not a GPU observation.

`AnalysisTarget` already carries `namespace`, `node`, `pod`, and `node_source` at [`base.py:AnalysisTarget`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/base.py:27). Downstream:

- Planning stores node/pod/workload in [`plan.py:InvestigationPlan`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/plan.py:17).
- Kubernetes applies them through [`kubernetes.py:_scope_target`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:3209).
- Prometheus builds pod/namespace selectors in [`prometheus.py:_queries_for`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/prometheus.py:295).
- Evidence eligibility compares observed entities with effective pod/node/namespace in [`pipeline.py:_evidence_context`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:2219) and [`evidence_blackboard.py:EvidenceEligibility.from_fact`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/evidence_blackboard.py:177).
- The system collector uses `node_source` to distinguish alert nodes from inferred nodes in [`system.py:SystemCollector.collect`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/system.py:663).

## 2. Existing plan-stage precedent

[`pipeline.py:plan_stage`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:847) already performs post-planning scope enrichment:

1. Build the plan.
2. Pin immutable identities for resolved alerts.
3. Optionally resolve free-text targets.
4. For an unresolved alert with namespace plus pod, call [`kubernetes.py:resolve_live_pod_node`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:3806).
5. Mutate `state.plan.pod` and `state.plan.node`.
6. Call [`pipeline.py:_apply_effective_target`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:437), which persists the scoped target for evidence, ranking, and the harness.

The resolver’s exact mechanism is:

- Exact Pod GET.
- Complete namespace Pod list, bounded to 10 pages/500 items.
- Exact occurrence name, then generated-name stem, then workload prefix.
- Prefer unhealthy pods.
- Accept ambiguity only when there is one pod or all candidates share one node.
- Fall back to the deleted Pod’s own Event node.

Those rules live in [`pod_name_stem`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:3246), [`_best_unambiguous_pod`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:3638), and [`_best_live_target_pod`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:3653).

This is the correct seam for quantity derivation: after the plan is built and resolved-alert pinning runs, but before the existing pod/node resolver and final `_apply_effective_target`.

One adjustment is necessary: `_apply_effective_target` scopes from `declared_target`, while `_scope_target` currently labels any different planned node as `"plan"`. Preserve a successful derived `state.target.node_source` when the derived node equals `plan.node`; never mutate `declared_target`.

## 3. Derivation sources

### Prometheus: no viable per-node GPU metric today

The fixed query set contains:

- `up`
- `container_memory_working_set_bytes`
- `container_cpu_usage_seconds_total`
- `kube_pod_container_status_restarts_total`
- `kube_pod_status_phase`
- `runai_queue_allocated_gpus`
- `runai_queue_requested_gpus`
- `runai_project_allocated_gpus`
- `runai_project_requested_gpus`

See [`prometheus.py:_queries_for`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/prometheus.py:295) and the drill-down allowlist description at [`drilldown.py:_KNOWN_PROMQL_SERIES`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/drilldown.py:2092).

No `kube_node_status_capacity`, `kube_node_status_allocatable`, DCGM readiness, or other per-node GPU-count series appears. The only node Prometheus follow-up is memory headroom, not GPU capacity.

Therefore a `fired_at` versus `fired_at-30m` GPU diff is not implementable from a metric name already established by this repository. A later temporal version should be added only after a real per-node gauge is captured, fixture-pinned, and added to the known-series contract.

### Run:ai MCP

The base Run:ai collector already gathers `get_cluster_physical_inventory` unconditionally through [`runai_mcp.py:gather_runai_via_mcp`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/runai_mcp.py:34) and [`_gather_physical_inventory`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/runai_mcp.py:90). It resolves a name to a cluster UUID through [`resolve_runai_cluster_id`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/runai_mcp.py:206).

That currently happens during evidence collection, after plan scope is fixed. Expose a narrow shared helper in `runai_mcp.py`; do not import private drill-down handlers into the pipeline.

The drill-down registry advertises:

- `get_cluster_physical_inventory`: GPU-node/model inventory plus total, allocatable, allocated, and free GPU values.
- `get_cluster_infrastructure_health`: degraded nodes, Kubernetes conditions, and taints.

See [`drilldown.py:_domain_tools`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/drilldown.py:2751), [`_tool_runai_cluster_physical_inventory`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/drilldown.py:3898), and [`_tool_runai_cluster_infrastructure_health`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/drilldown.py:3922).

MCP is not structurally drill-down-only—the base collector already uses it—but `plan_stage` currently calls only the change collector, planner, free-text resolver, and Kubernetes live-pod resolver. It has no registry/tool invocation path today.

### Primary and fallback

Primary: `get_cluster_physical_inventory`.

For each strictly validated per-node row:

```text
deficit(node) = physical_total_gpu(node) - allocatable_gpu(node)
```

Promote only when:

- The alert is firing/unresolved.
- Every GPU-bearing row needed for the decision is parseable and nonnegative.
- `allocatable <= physical_total`.
- Exactly one node has `deficit > 0`.
- Every other GPU node has deficit zero.
- The node name is non-empty and valid.
- Do not use allocated/free values for selection; workload placement can change those without a readiness loss.

Use `node_source="derived_from_inventory_deficit"`. Do not call it `derived_from_metric_diff`.

Fallback: a complete Kubernetes Nodes list, using the already-understood `status.capacity["nvidia.com/gpu"]` and `status.allocatable["nvidia.com/gpu"]` representation in [`kubernetes.py:_node_summary`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:5759) and [`_node_gpu_value`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:6003). Apply the same unique-positive-deficit rule and require a complete list.

`get_cluster_infrastructure_health` should only corroborate the selected node. Its registered contract has no GPU quantity or historical baseline, so a unique degraded node alone must not promote scope.

If Run:ai’s per-node JSON field names are not fixture-pinned from the real MCP payload, fail closed or use the Kubernetes fallback. The only inventory shape currently parsed in code is aggregate `byGpuModel` in [`runai_cluster_gpu_model`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/runai_mcp.py:253).

## 4. Honest promotion

Current provenance behavior:

- `resolve_target` writes `"alert"` when a node label/annotation supplied the node.
- `_scope_target` writes `"plan"` for a different plan node.
- `SystemCollector.collect` treats only `""`/`"alert"` as alert provenance.
- [`kg_enrichment.py:_prior_is_context_compatible`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/kg_enrichment.py:941) deliberately refuses to use plan-derived nodes to disqualify historical cards.
- `node_source` already appears in `response.context["target"]` because [`synthesize_stage`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:2501) serializes `state.target.__dict__`.

Add `PipelineState.scope_derivation`, populated only on success:

```json
{
  "dimension": "node",
  "value": "gpu-node-7",
  "source": "runai_cluster_physical_inventory",
  "method": "unique_physical_allocatable_deficit",
  "evidence_role": "scope_seed_not_causal_evidence",
  "query": "MCP get_cluster_physical_inventory",
  "deficit": 7
}
```

Honor derived scope in:

- `plan.node` and effective `state.target.node`.
- Kubernetes/system collection routing.
- `_evidence_context`, so an independently verified observation naming that node can become eligible.
- Prometheus/Loki only when their returned labels independently prove the same node; their verification lives in [`prometheus.py:_prometheus_target_scope`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/prometheus.py:1191).
- Response context and report wording.

Keep it unverified in:

- `declared_target`: it must remain the immutable label-derived target.
- Historical system-log placement. Do not modify [`system.py:_scan_node`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/system.py:893); current inventory does not prove the alert historically belonged to that node.
- Historical knowledge-card compatibility.
- Blackboard/ranking/remediation: the derivation receipt is a scope seed, not an artifact and not causal support.
- `target_identity_verified`: never stamp it merely because derivation succeeded. Producers must still prove the returned entity. The investigator’s auto-attachment requires present+scoped plus this flag at [`investigator.py:_attach_typed_artifacts`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/investigator.py:740), and the harness uses it for generic-alert safety at [`harness.py:_target_verified_artifact`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/harness.py:481).

The evidence demotion rules remain unchanged. `target_scope_verified=False` still becomes `target_scope_unverified` in [`evidence_blackboard.py:_COLLECTOR_DEMOTION_FLAGS`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/evidence_blackboard.py:891). Derivation narrows queries; it does not bypass response-label/entity verification.

Report wording needs an explicit change because [`pipeline.py:_detail_from`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:4280) currently re-runs `resolve_target` and therefore sees only alert metadata. Pass the effective target separately and render:

> Investigation scope candidate: `node/gpu-node-7` — derived from a unique physical-versus-allocatable GPU deficit; the alert did not declare a node.

Do not place the node under an unqualified “alert target” heading.

## 5. Failure containment and budget

Any of these must return without changing target, plan, warnings, artifacts, report text, or response context:

- Feature flag off.
- Classifier false.
- Resolved alert.
- Missing configuration/authentication.
- Timeout.
- Malformed/incomplete payload.
- Missing or invalid quantities.
- No positive deficit.
- More than one positive-deficit node.
- Primary/fallback disagreement.

The current plan stage has no stage-specific timeout. The outer orchestrator applies the default 900-second hard deadline in [`orchestrator.py:analyze`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/orchestrator.py:116). The evidence deadline reserves 150 seconds, leaving approximately 750 seconds from analysis start under defaults; see [`pipeline.py:_finalization_reserve_seconds`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:272) and [`_evidence_deadline_monotonic`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:301).

Existing source ceilings are 120 seconds for Run:ai and Prometheus and 300 seconds for planner LLM calls in [`config.py:load_settings`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/config.py:243).

Add one code constant:

```text
_QUANTITY_SCOPE_DERIVATION_TIMEOUT_SECONDS = 10.0
```

Use one `asyncio.wait_for` bounded by the smaller of 10 seconds and remaining evidence-budget time. Select the primary or fallback before starting the round; do not begin a second round after timeout. Existing MCP retries remain contained by the outer 10-second cap.

## End-to-end flow

```text
Alert
  → new_state / resolve_target
  → scope-less quantity classifier
  → ordinary deterministic/LLM plan
  → resolved-alert guard
  → one bounded inventory-deficit derivation round
      inconclusive/error/timeout → unchanged current behavior
      unique node →
        plan.node = node
        state.target.node = node
        node_source = derived_from_inventory_deficit
        scope_derivation receipt = non-evidence provenance
  → existing live-pod/node resolution, without overriding derived provenance
  → _apply_effective_target
  → node-scoped collectors
  → each returned observation must independently name/verify the node
  → normal blackboard target/window eligibility
  → eligible observations may affect ranking/playbook/KB
  → derivation seed itself never affects ranking
  → report labels node as derived, not alert-declared
```

## Edit points

- [`base.py:resolve_target`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/base.py:644): add the dimensionless numeric-alert classifier beside the existing metadata parser.
- [`pipeline.py:PipelineState`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:138): add optional `scope_derivation`.
- [`pipeline.py:plan_stage`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:847): invoke the single bounded derivation round and mutate only on conclusive success.
- [`pipeline.py:_apply_effective_target`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:437): preserve derived `node_source` across reapplication from immutable `declared_target`.
- [`runai_mcp.py:_gather_physical_inventory`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/runai_mcp.py:90): expose a focused, authenticated inventory read and strict unique-deficit parser.
- [`kubernetes.py:_node_gpu_value`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/collectors/kubernetes.py:6003): add/reuse a complete-list unique-deficit fallback without duplicating GPU quantity parsing.
- [`pipeline.py:_detail_from`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/services/pipeline.py:4280): render qualified derived-scope wording.
- [`config.py:Settings`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/agent/app/config.py:68), [`values.yaml`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/charts/runai-rca/values.yaml:474), and [`agent.yaml`](/Users/bohyunchoi/Github/runaiRCA/.claude/worktrees/nginx-headers/charts/runai-rca/templates/agent.yaml:101): add the rollout flag.

No changes are needed in `EvidenceEligibility`, ranking, harness, system historical verification, or KG matching.

## Edge cases

- Multi-node simultaneous drop: inconclusive; never collapse to the largest node.
- Strictly unique largest drop but another smaller drop: inconclusive because more than one node changed.
- Node disappeared entirely: missing row is unknown, not zero; no promotion.
- `capacity` and `allocatable` both fell together: no current deficit; inconclusive.
- Negative value, `allocatable > total`, NaN, or partial payload: inconclusive.
- Counter reset: reject counter-based derivation entirely; this feature requires gauges/inventory quantities.
- Threshold expression mixed with alert value: classifier may trigger, but expression values never drive node selection.
- Resolved alert: current inventory/health cannot backdate scope; no promotion.
- Long-running firing alert: current deficit may scope ongoing collection, but report must call it current derived scope, not proof of the original trigger.
- Prometheus absent: irrelevant to the first version.
- Run:ai unavailable: use the Kubernetes fallback only if selected before the one bounded round and its node list is complete.
- Inventory and infrastructure health disagree: inventory quantity result may scope collection, but health is not allowed to override or independently select a node.

## Test plan

Unit tests:

- Positive classifiers for the incident’s `labels={} value=8` / `value=1` shape and JSON `__values__`.
- Reject explicit node/pod/namespace, nonnumeric input, nonempty embedded labels, NaN/infinity, malformed JSON, and non-GPU quantity alerts.
- Unique inventory deficit promotes.
- Zero deficit, ties, multiple deficits, missing node name, incomplete rows, and invalid quantities do not.
- Timeout leaves target, plan, warnings, and serialized context unchanged.
- `declared_target.node` remains empty while effective target carries the derived node.
- `_apply_effective_target` preserves `derived_from_inventory_deficit`.
- Historical system logs remain partial for inventory-derived scope.
- Report contains “derived/not alert-declared” wording.
- Scope receipt is absent from blackboard facts and eligible evidence IDs.

Replay-style test:

- Construct `Ready GPUs` with no node/namespace/pod labels and `__value_string__="[ var='A' labels={} value=8 ], [ var='C' labels={} value=1 ]"`.
- Mock one GPU node with `physical=8`, `allocatable=1` and all other nodes at zero deficit.
- Assert effective target node/source and plan node.
- Feed one independently node-verified, in-window observation.
- Assert that observation can become eligible, while the scope receipt itself is not evidence.
- Assert response context and report expose the derivation provenance.
- Repeat with tie/timeout and compare the response-relevant state to today’s unmodified path.

## Size and rollout

Estimated change: roughly 180–250 production lines plus 150–220 test lines across 6–8 files.

Use a chart flag, default off initially. This changes an evidence trust boundary, and the Run:ai per-node inventory payload is not fixture-pinned in the repository. Enable it for replay/canary runs first; make it default-on only after the strict adapter is validated against captured MCP payloads. Avoid configurable thresholds—the exact-one-positive-deficit rule and 10-second cap are sufficient.
