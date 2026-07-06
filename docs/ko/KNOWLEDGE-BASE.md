# Knowledge Base

> **관점:** 에이전트가 인시던트를 보기 *전에* 이미 아는 것 — 모든 RCA의 근거가 되는
> 큐레이션된 카탈로그와 온톨로지 그래프입니다.
> **이 문서에서 다루는 것:** 다섯 개의 큐레이션 카탈로그 · 플랫폼 아키텍처 토폴로지 ·
> 파일 ↔ TypeDB 이중 로드 · 인제스트(적재) 및 지식 승격 · 그래프 질의.

큐레이션된 지식은 **이중 로드**됩니다: `agent/app/knowledge.py`의 파일 매처
(**TypeDB 없이도** 동작 — 항상 사용 가능)와, 동일한 사실을 그래프로 미러링하는
TypeDB 로더(`agent/ontology/load_*.py`)입니다. 불변 규칙은 다음과 같습니다: TypeDB가
꺼진 상태에서도 RCA는 완전히 동작하며, TypeDB는 "켜면 더 똑똑해지는" 계층일 뿐 결코
강한 의존성이 아닙니다.

## 큐레이션 카탈로그

모두 `agent/knowledge/` 아래에 있으며 에이전트 이미지에 함께 배포됩니다.

| 카탈로그 | 파일 | 인식 기준 | 용도 |
|---|---|---|---|
| **Failure modes** | `failure_modes.yaml` | 증상 키워드(모든 패밀리 대상) | 증상별 정확한 조치 방안 |
| **Run:ai known issues** | `runai_known_issues.yaml` | 시그니처 키워드, 버전 인식 | 특정 버그 + 영향/수정 버전을 헤드라인으로 표시 |
| **Built-in alerts** | `runai_alerts_catalog.yaml` | 알림 이름 | 문서화된 Run:ai 알림과 그 수정 방안 인식 |
| **NVIDIA XID catalog** | `xid_catalog.yaml` | XID 코드 | GPU 하드웨어 결함 경로 + 인과 체인 |
| **Platform architecture** | `runai_architecture.yaml` | 컴포넌트 이름(증상의 `component:` 태그 경유) | 의존성 점검 경로 + DB 스키마 힌트 |

매칭은 부분 문자열 우선(정확)이며, 아무것도 매칭되지 않을 때 보수적인 **BM25 + 동의어**
재현율 폴백(`agent/app/bm25.py`)이 동작합니다 —
[RCA Pipeline](RCA-PIPELINE.md)을 참조하십시오.

### 근본 원인 패밀리 (15개)

이 분류 체계는 온톨로지의 척추이자 정직성 게이트입니다. 결정론적 랭커는 그 일부만
점수화하며, **시그니처 승격**이 나머지를 헤드라인으로 표시합니다(따라서 랭커가 지목할 수
없는 `gpu_hardware_error`와 known-issue 패밀리도 여전히 노출됩니다).

`node_kubelet_pressure`, `runai_scheduling_quota`, `k8s_scheduling_error`,
`runai_control_plane_error`, `k8s_control_plane_error`, `workload_startup_error`,
`image_pull_error`, `gpu_hardware_error`, `network_fabric_error`,
`cluster_network_error`, `k8s_storage_error`, `storage_backend_error`,
`workload_runtime_error`, `observability_accuracy`, `platform_auth_error`
(+ `insufficient_evidence`).

패밀리 추가 = `schema.tql` 서브타입 + `failure_modes.yaml` 블록 + 두 로더의
`FAMILIES` 집합 + 오케스트레이터의 `_family_label`/`_FAMILY_EXPLANATION`. 랭커는
건드리지 않습니다. 가드레일 테스트가 스키마 ↔ 로더 동기화를 강제합니다.

## 플랫폼 아키텍처 토폴로지

`knowledge/runai_architecture.yaml`은 Run:ai 플랫폼/컨트롤 플레인 아키텍처 다이어그램에서
큐레이션한 컴포넌트 맵이며, 이름은 **실제 self-hosted 클러스터에 맞춰 보정**되었습니다
(`kubectl get deploy,ds,sts -n runai / -n runai-backend`). 클러스터 측과 `runai-backend`
컨트롤 플레인에 걸쳐 약 35개 컴포넌트가 있습니다. 각 항목:

| 필드 | 의미 |
|---|---|
| `layer` | `cluster` · `control_plane` · `external` |
| `purpose` / `failure_effect` | 하는 일 / 다운되면 무엇이 깨지는지 |
| `depends_on` | 필요로 하는 컴포넌트 — 트러블슈팅 순서 |
| `owns_schema` | 소유하는 컨트롤 플레인 Postgres 스키마 |
| `checks` | 즉시 실행 가능한 `kubectl` 명령 |

세 개의 소비자(`agent/app/knowledge.py`):

1. **점검 경로** — `failure_modes.yaml` 증상은 `component:`를 지닙니다. 플레이북은 해당
   컴포넌트의 실패 영향, `dependency_path()` BFS 점검 순서, 그리고 그 점검들을
   렌더링합니다.
2. **DB 스키마 힌트** — postgres 드릴다운의 `sql_select` 설명이 스키마 소유권으로
   보강됩니다(`workloads = runai-backend-workloads; audit =
   runai-backend-audit-service; …`).
3. **그래프 조인** — 향후 라이브 인시던트 사실과의 조인을 위해 TypeDB로 미러링됩니다
   (`control_plane_component` + `depends_on`).

## TypeDB 온톨로지

선택적 TypeDB 3.x 지식 그래프(`typedb.enabled`, Helm 기본값 **on**)는 pgvector 유사도와
레이블 중첩으로는 표현할 수 없는 관계형 추론을 오케스트레이터에 제공합니다. 스키마:
`agent/ontology/schema.tql`. 이는 합성(synthesis) 시점 무렵에 **오케스트레이터에 의해**
참조됩니다 — 별도의 에이전트가 아니며, 병렬 수집기도 아닙니다.

**계층**
- *인프라 / 토폴로지* — `cluster`, `node`, `namespace`, `project`, `queue`,
  `workload`, `pod`, `control_plane_component` (`depends_on` 포함).
- *인시던트 / RCA* — `alert`, `incident`(이전 RCA를 질의할 수 있도록 `analysis_summary`를
  소유), `analysis_run`.
- *지식* — `symptom`(`keyword` 소유), `root_cause`, `action`, 그리고 `leads_to` 인과
  체인을 가진 `xid_error` GPU 결함 카탈로그.

**추론 함수**(`ontology/functions.tql`, TypeQL 3.11.x로 검증):
`fixes_for_family`, `fixes_for_xid`, `xids_for_gpu_model`, `root_xids_for`.

### 데이터가 들어오는 방식

| 경로 | 로더 | 소스 | 게이트 |
|---|---|---|---|
| Schema + functions | `load_schema` / `load_functions` | `schema.tql` / `functions.tql` | Helm post-install/upgrade 훅 |
| Curated knowledge | `load_knowledge`, `load_xids`, `load_alerts`, `load_known_issues`, `load_architecture` | 위의 카탈로그들 | 버전 관리되는 파일, 스키마 잡에서 실행 |
| Incidents + topology | `ontology/ingest.py` (cron) | Postgres `incidents`/`alerts` | `resolvedGraceHours` 이전에 resolved됨; `requireReview=false`가 아니면 리뷰 게이트 적용 |
| Knowledge promotion | `ingest.py --promote-knowledge` | 운영자가 확인한 RCA | resolved + 순긍정 피드백 → `confirmed:<alert>` 증상 |

인제스트 **CronJob**(`typedb.ingest.schedule`, 기본 3시간마다)은 resolved된 인시던트를
그래프로 투영합니다. 유예 창은 늦은 피드백 / 재분석이 안정되도록 하며, 재발화된 인시던트는
`firing`으로 되돌아가 제외됩니다. `requireReview: false`(기본값)에서는 리뷰 여부와 무관하게
resolved된 인시던트를 인제스트합니다 — 리뷰되지 않은 자동 분석을 그래프에서 제외하려면
`true`로 전환하십시오.

### 그래프 질의

`ontology/query.py`는 읽기 전용 인트로스펙션 CLI입니다 — TypeQL을 직접 작성하지 않고도
인제스트가 실제로 무엇을 투영했는지 확인합니다:

```bash
kubectl exec -n <ns> deploy/<release>-agent -- \
  python -m ontology.query --incident INC-...-000023   # one incident
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --recent 20
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --count
```

또는 서버를 포트 포워딩하여(`kubectl port-forward svc/<release>-typedb 1729:1729
8000:8000`) **TypeDB Studio**를 연결하고 `localhost:1729`(db `runai_rca`,
`admin`/`password`, TLS off)에 접속하십시오. 예시 — 어떤 알림에 대한 이전 인시던트,
`enrich()`가 실행하는 바로 그 질의:

```typeql
match
  $a isa alert, has alert_name "Memory major page faults ...";
  (incident: $i, member: $a) isa grouped_into;
  $i isa incident, has incident_id $iid, has analysis_summary $sum;
select $iid, $sum;
```

## 함께 보기

- [Data Stores](DATABASE.md) — 두 저장소에 대한 테이블 수준 참조.
- [RCA Pipeline](RCA-PIPELINE.md) — 이 지식이 분석 중에 어떻게 소비되는지.
