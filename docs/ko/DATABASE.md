# Data Stores

> **관점:** 어떻게 만들어졌는가(데이터) — 두 개의 저장소와 각각이 소유하는 것.
> **이 문서에서 다루는 것:** PostgreSQL 테이블 · TypeDB 온톨로지 · 인제스트 경로 · 연결 설정.

Run:AI RCA는 서로 다른 역할을 가진 두 개의 저장소를 사용합니다. 런타임 흐름은
[Architecture](ARCHITECTURE.md)를 참조하십시오. 이 문서는 데이터 구조 참조입니다.

**이 문서는 누구를 위한가:** 기록이 어디에 있는지 알아야 하는 운영자와, 한 배포에 왜 두
데이터베이스가 있는지 이해해야 하는 개발자를 위한 문서입니다. PostgreSQL은 작업 중인 사건
파일이고, TypeDB는 그 파일의 승인된 부분으로 만든 선택 사항 관계 인덱스입니다.

| 저장소 | 역할 | 소유자 | 필수 여부 |
|---|---|---|---|
| **PostgreSQL** | 운영 신뢰의 원천: 인시던트, 알림, RCA 결과, 운영자 피드백, 유사도 벡터 | Go 백엔드 | 예 (로컬 개발용 인메모리 폴백 제공) |
| **TypeDB** | 온톨로지 지식 그래프: 합성 시점의 관계형 추론을 위한 타입 지정 엔티티 + 관계 | 에이전트 | 아니요 (`typedb.enabled`, Helm 기본값 on) |

그래프는 Postgres로부터 **파생**됩니다 — 두 번째 신뢰의 원천이 아닌 적격성 게이트 기반
투영입니다. Dashboard 승인을 받고 grace period가 지난 resolved 인시던트만 담습니다
(`typedb.ingest.requireApproval=true`가 기본값).

```mermaid
flowchart LR
  BE[Backend] <-->|"read/write · pgvector similarity"| PG[(PostgreSQL + pgvector)]
  PG -.->|eligible-incident ingestion| TDB[(TypeDB ontology)]
  BE -->|similar_incidents + feedback_hints| AG[Agent orchestrator]
  AG -->|"enrich / graph_remediation"| TDB
```

**pgvector** 유사도는 에이전트가 아니라 **백엔드**(Go)가 소유합니다: 백엔드가 코사인
검색을 실행하고 그 매칭 결과를 각 `/analyze` 요청에 전달합니다. 에이전트
**오케스트레이터**는 **TypeDB** 측을 소유합니다 — 분석 중에 그래프를 참조합니다.
[RCA Pipeline](RCA-PIPELINE.md)과 [Knowledge Base](KNOWLEDGE-BASE.md)를 참조하십시오.

---

## 1. PostgreSQL (운영)

### 작업에 따라 데이터 찾기

현재 인시던트, 알림, analysis run, 피드백, 유사도 검색은 PostgreSQL을 사용합니다. TypeDB는
선택 사항인 토폴로지와 승인 이력 관계에만 사용하며, 두 번째 운영 신뢰 원천이 아닙니다.

테이블은 시작 시 백엔드가 자동 생성합니다(`backend/store_postgres.go`).

| 테이블 | 목적 | 주요 컬럼 |
|---|---|---|
| `incidents` | 상관된 알림 그룹 | `incident_id` (PK), `correlation_key`, `title`, `severity`, `status`, `fired_at`, `resolved_at`, `alert_count` |
| `alerts` | 개별 알림 + 해당 RCA | `alert_id` (PK), `incident_id` (FK), `fingerprint`, `occurrence_count`, `occurrence_pods` (JSONB), `labels`/`annotations` (JSONB), `analysis_summary`/`analysis_detail`, `analysis_quality`, `capabilities`/`missing_data`/`warnings`/`artifacts` (JSONB) |
| `incident_embeddings` | 유사도 메모리 | `incident_id` (PK), `alert_id`, `analysis_summary`/`analysis_detail`, `labels` (JSONB), `vector_json` (JSONB), `embedding vector(384)` + HNSW cosine index |
| `rca_feedback` | 운영자 투표 | `feedback_id` (PK), `target_type`, `target_id`, `vote` (`up`/`down`), `author`, `created_at` |
| `rca_comments` | 운영자 메모 | `comment_id` (PK), `target_type`, `target_id`, `body`, `author`, `created_at` |
| `analysis_runs` | RCA 실행 이력 | `run_id` (PK), `source` (`auto`/`manual`/`chat`/`feedback`), `status`, `target_type`, `target_id`, `analysis_*`, `created_at` |

**유사도 검색**: `incident_embeddings.embedding`(pgvector, HNSW cosine)이 기본 경로이며,
pgvector를 사용할 수 없을 때 JSONB 희소 벡터 코사인 폴백이 동작합니다. 384차원 벡터는 RCA
텍스트의 결정론적 피처 해시입니다(모델 의존성 없음) — `backend/memory.go`를 참조하십시오.
`labels`/`annotations` JSONB는 인제스트가 소비하는 가장 풍부한 엔티티
소스입니다(cluster/node/queue/etc.).

---

## 2. TypeDB (온톨로지 지식 그래프)

스키마: `agent/ontology/schema.tql` (TypeQL 3.x). 세 개의 계층.

### 인프라 계층 — *인제스트로 채워짐*
`cluster`, `node`, `namespace`, `project`, `queue`, `workload`, `pod`,
`control_plane_component`.
GPU는 별도 엔티티가 아니라 `node`/`queue`/`project`의 속성(`gpu_allocated`,
`gpu_requested`)으로 모델링됩니다.

### 인시던트 / RCA 계층 — *인제스트로 채워짐*
`alert`, `incident`(이전 RCA를 질의할 수 있도록 `analysis_summary` 소유),
`analysis_run`.

### 지식 계층 — *큐레이션됨; `knowledge/` 카탈로그에서 시드됨*
`symptom`(매칭용 `keyword` 소유), `root_cause`, `action`, 그리고 `xid_error` GPU 결함
카탈로그(`leads_to` 체인 포함)와 `control_plane_component` 플랫폼 토폴로지(`depends_on`
포함). 이는 오케스트레이터가 참조하는 "이 증상 → 이 원인 → 이 조치로 수정됨" 지식입니다.
다섯 개의 로더가 공급합니다 — [How data gets in](#3-how-data-gets-in)과
[Knowledge Base](KNOWLEDGE-BASE.md) 문서를 참조하십시오.

### 근본 원인 분류 체계 (15개 패밀리, `sub root_cause`)
`node_kubelet_pressure`, `runai_scheduling_quota`, `k8s_scheduling_error`,
`runai_control_plane_error`, `k8s_control_plane_error`, `workload_startup_error`,
`image_pull_error`, `gpu_hardware_error`, `network_fabric_error`,
`cluster_network_error`, `k8s_storage_error`, `storage_backend_error`,
`workload_runtime_error`, `observability_accuracy`, `platform_auth_error`
(+ `insufficient_evidence`). 로더의 `FAMILIES` 집합 및
`agent/app/services/root_cause_ranking.py`와 동기화 상태를 유지해야 하며, 가드레일
테스트가 이를 강제합니다.

### 관계
- **토폴로지**: `scopes` (cluster→node/project), `runs_on` (node→pod),
  `belongs_to` (workload→pod), `in_project`, `submitted_to` (workload→queue),
  `contains` (namespace→pod/workload/component), `depends_on` (component→component)
- **인시던트**: `grouped_into` (incident←alert), `analyzed_by`, `similar_to`
- **지식**: `has_symptom`, `indicates` (symptom→cause), `has_cause`,
  `fixed_by` (cause→action), `resolved_by` (symptom→action), `supported_by`
  (←evidence), `emits`, `applies_to` (xid→gpu_model), `leads_to` (xid→xid)

### 채워짐 vs 모델링됨
| 상태 | 엔티티 / 관계 |
|---|---|
| ✅ 채워짐 (`ontology/ingest.py`) | 인프라 + 인시던트 계층 + 토폴로지/`grouped_into` |
| ✅ 지식 (`load_knowledge` / `load_troubleshooting` / 기타 `load_*`) | symptom/cause/action과 실행형 runbook 단계·전이·결론·조치, XID, component 의존성 |
| 🟦 승격됨 (`ingest.py --promote-knowledge`) | 운영자가 확인한 RCA로부터 `confirmed:<alert>` 증상 → 패밀리 → 조치 |
| ⬜ 모델링됨, 아직 미공급 | `evidence`, `analysis_run`, `similar_to`, `supported_by`, GPU 속성 |

---

## 3. How data gets in

| 경로 | 스크립트 | 소스 | 게이트 |
|---|---|---|---|
| Schema + functions | `load_schema` / `load_functions` | `schema.tql` / `functions.tql` | Helm post-install/upgrade 훅 (`typedb-schema-job.yaml`) |
| Curated knowledge | `load_knowledge`, `load_troubleshooting`, `load_xids`, `load_alerts`, `load_known_issues`, `load_architecture` | `knowledge/` 카탈로그들 | 버전 관리되는 파일, 스키마 잡에서 실행 |
| Topology + incidents | `ontology/ingest.py` (CronJob) | Postgres `incidents`/`alerts` | Dashboard 승인(`user_approved_at`) 후 resolved 상태로 `resolvedGraceHours` 이상 경과. `requireReview`는 deprecated |
| Knowledge promotion | `ingest.py --promote-knowledge` | 운영자가 확인한 RCA | resolved + 순긍정 피드백 |

**오케스트레이터**는 분석 중에 TypeDB를 참조합니다
(`agent/app/services/kg_enrichment.py`): 노드 blast radius(영향 범위), 동일 알림의 이전
인시던트, 그래프에서 파생된 조치 방안. TypeDB가 꺼져 있거나 도달 불가일 때는 빈 컨텍스트로
격하됩니다. 그래프는 `python -m ontology.query`(`--incident` / `--recent` / `--count`)
또는 TypeDB Studio로 조사하십시오.

---

## 4. 연결 / 설정

| 환경 변수 | 기본값 | 비고 |
|---|---|---|
| `ENABLE_TYPEDB` | `false` (Helm이 `typedb.enabled`에서 설정) | 마스터 스위치 |
| `TYPEDB_ADDRESS` | `localhost:1729` | 클러스터 내부: `<release>-typedb:1729` |
| `TYPEDB_DATABASE` | `runai_rca` | |
| `TYPEDB_USERNAME` / `TYPEDB_PASSWORD` | `admin` / `password` | CE 기본값 — PoC를 넘어서면 재정의 |
| `POSTGRES_DSN` | — | 백엔드 Postgres(에이전트 수집기/인제스트도 읽음) |
| `RUNAI_DB_DSN` | — | **Run:ai 컨트롤 플레인** Postgres에 대한 선택적 읽기 전용 DSN; 플랫폼 스키마(workloads/audit/…)에 대한 postgres 드릴다운의 `sql_select`를 활성화합니다. 읽기 전용 롤을 사용하십시오. |

수집에 `RUNAI_DB_DSN`을 사용하면 audit/history 읽기는 UTC 세션에서 실행됩니다.
`timestamp without time zone` 값은 Run:ai UTC로 해석하고, 결과 관찰에는
`naive_timestamps_assumed_utc: true`를 선언합니다. audit-table 실패는 격리되므로
성공한 테이블은 계속 사용할 수 있고, 실패하거나 발견 제한으로 건너뛴 테이블은
partial/missing data로 보고됩니다. Run:ai 컨트롤 플레인 DB 연결 실패도 정상 Postgres 점검이나
인과 증거가 아니라 사용 불가 문맥으로 명시적으로 보입니다.

TypeDB는 단일 노드 `StatefulSet` + PVC로 배포됩니다
(`charts/runai-rca/templates/typedb.yaml`). Community Edition은 단일 노드이며,
HA/클러스터링은 유료 Enterprise 등급입니다.
