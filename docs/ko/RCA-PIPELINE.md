# RCA Pipeline

> **관점:** Agent가 하나의 알림을 하나의 근거 있는 RCA로 바꾸는 방법 — 모든 단계를 순서대로.
> **이 문서에서 다루는 것:** 오케스트레이터 흐름 · 플래너 · 7개 수집기 · 중앙 조사 루프 ·
> 수집기별 자율 드릴다운 · 시그니처 매칭 + BM25 리콜 · 랭킹 · 자기 점검 / 재분석 · 종합 · 런타임 하네스 ·
> 증거 표현 · 안전 봉투(safety envelope).

Agent는 단일 프롬프트가 **아닙니다**. 단일 전체 데드라인(deadline) 하에서 하나의
오케스트레이터(orchestrator)(`agent/app/services/orchestrator.py`)가 실행하는 컴포넌트 지향
다중 에이전트 파이프라인(pipeline)입니다. 모든 LLM 단계는 선택적입니다: LLM이 구성되지 않았거나
어떤 실패가 발생하면, 파이프라인은 결정론적 경로로 저하(degrade)되며 여전히 리포트를 생성합니다.
일곱 파이프라인 단계는 시작 시 한 번 빌드되는 `runai_rca_pipeline` 컨트롤러 워크플로
(`agent/configs/runai_rca_engine.yml`) 아래에서 NAT 함수로 실행됩니다. NAT 엔진이
비활성화되었거나 실패하면, 동일한 단계가 실패 폴백으로 프로세스 안에서 직접 실행됩니다.

**쉽게 기억하는 방법:** 이 파이프라인은 신중한 조사 체크리스트입니다. 먼저 알림의 범위를
파악하고, 사실을 모은 뒤, 스스로의 결론을 반박해 보고, 마지막으로 RCA가 사실보다 더 많은
말을 하지 않는지 확인합니다.

```mermaid
flowchart TB
  REQ([/analyze 요청]) --> ORCH([오케스트레이터])
  ORCH --> NAT{NAT 컨트롤러 사용 가능?}
  NAT -->|예| ENRICH
  NAT -->|아니오 또는 실패| ENRICH

  ENRICH["1 · 그래프 보강\n과거 인시던트 · 영향 범위"] <-->|읽기 전용 문맥| TDB[(TypeDB 온톨로지)]
  ENRICH --> PLAN["2 · 조사 계획\n범위 · 가설 · probe 우선순위"]

  subgraph EVIDENCE["3 · 증거 순환 — 모든 수집기 결과를 기다림"]
    direction TB
    INV["선택적 중앙 조사 루프\n다음 독립·판별 probe 선택"] -.-> BASE
    BASE["기본 병렬 수집\nRun:ai · Kubernetes · Prometheus · Loki · Postgres · System · Change"]
    BASE --> FOLLOW["결정론적 후속 점검\n예: 이벤트 → quota/PVC → 메트릭"]
    FOLLOW --> DRILL["수집기별 드릴다운\n읽기 전용, 각 도메인 도구만 사용"]
    DRILL --> TRACE["Evidence ID + trace-v3\n가설 · probe · evidence 연결"]
  end

  PLAN --> BASE
  TRACE --> RANK["4 · 시그니처 매칭 + BM25 + 랭킹"]
  RANK --> CHECK["5 · 자기 점검\n선두 원인 반박 또는 신뢰도 보정"]
  CHECK --> MORE{추가 증거가\n필요한가?}
  MORE -->|예: 목표 재분석| BASE
  MORE -->|아니오| SYN["6 · 종합 + 그래프 조치 보강\n문제 · 원인 · 조치 · 부록"]
  SYN <-->|조치 조회| TDB
  SYN --> HAR["7 · 런타임 하네스\n수정, 신뢰도 하향 또는 보류"]
  HAR --> RESP([RCA + 증거 추적])
```

`trace-v3`만 공개·영속 reasoning 계약으로 사용합니다. 최종 선택은 정확한
`selected_hypothesis_id`로 기록하며, open-world 선택은 `mechanism_fingerprint`도
포함합니다. 내부 hypothesis ledger는 일시적인 작업 데이터로만 유지하고, 운영 budget
종료 정보는 trace가 아니라 로그와 progress event에 남깁니다.

전체 실행은 `asyncio.wait_for(analyze, ANALYSIS_DEADLINE_SECONDS)`로 감싸집니다
(기본값 **900초 / 15분**). 초과 시 멈춤(hang) 없이 우아하게 저하된 리포트를 반환합니다.
단계별 상한은 *의도적으로* 넉넉합니다(깊은 증거가 빠르지만 얕은 것보다 낫습니다). 전체 데드라인이
실제 한계입니다. Backend의 `AGENT_REQUEST_TIMEOUT_SECONDS`(960초)는 이보다 위에 유지되어야
합니다.

## 단계 안내: 무엇이 들어오고, 무엇이 나오며, 무엇이 멈추게 하는가

| 단계 | 입력 → 출력 | 멈추거나 제한하는 조건 |
| --- | --- | --- |
| Enrich | alert target → 승인 이력/토폴로지 문맥 | TypeDB는 선택 사항이며, 그래프 부재는 중단이 아닌 경고 |
| Plan | alert + 문맥 → 범위가 정해진 가설과 probe | 레이블이 부족하면 범위만 줄고 쓰기 권한이 생기지 않음 |
| Evidence | plan → collector artifact | 출처별 실패는 partial/unavailable evidence가 됨 |
| Rank | artifact → 순서가 있는 후보 | 시그니처도 live evidence의 뒷받침이 필요 |
| Self-check | 선두 후보 → 주의 사항/재분석 필요 여부 | LLM은 선택 사항이며 deadline이 추가 작업을 제한 |
| Synthesize | evidence → 운영자가 읽는 RCA | 결정론적 리포트, ko 한국어화는 산문 라인만 번역 |
| Harness | 초안 → 수정/신뢰도 하향/보류 응답 | hard evidence gate는 `insufficient_evidence`를 반환할 수 있음 |

```mermaid
flowchart LR
  P[Plan] --> I[중앙 조사 루프\n다음 판별 질문 선택]
  P --> D[Collector drill-down 루프\n각 collector의 도구만 사용]
  I --> E[Evidence artifact]
  D --> E
  E --> R[Rank, self-check, synthesis]
```

중앙 루프는 증거 평면 사이에서 다음 질문을 고릅니다. collector drill-down은 한 평면 안에
머뭅니다. 둘 다 읽기 전용이며, 조사가 끝났거나 같은 질문이 반복되거나 전체 deadline에 도달하면 멈춥니다.

---

## 1. Planner — think first

`agent/app/services/planner.py`는 알림 레이블, 대상, 지식 그래프(knowledge graph) 컨텍스트,
그리고 벡터 유사 인시던트를 바탕으로 **어떤 수집기가 실행되기 전에** `InvestigationPlan`을
구성하여, 에이전트가 항상 Run:ai 컨트롤 플레인(control plane) 전체를 긁어모으지 않도록 합니다
(정확도 관련 1순위 불만).

- **결정론적 코어**(항상): 키워드/레이블 휴리스틱이 각 수집기의 범위를 정하고 실패
  패밀리(failure family)별로 가설의 순서를 매깁니다.
- **네임스페이스 라우팅**: 플랫폼 네임스페이스 알림(`runai` / `runai-backend`)은 광범위한
  k8s + 시스템 증거로 확대되고, 사용자 워크로드(workload) 네임스페이스는 Run:ai 스케줄러
  (scheduler) 서브시스템에 집중합니다.
- **선택적 LLM 정제**: LLM이 구성되면 초점/가설/전략을 날카롭게 다듬습니다. 어떤 실패든 →
  결정론적 계획이 유지됩니다.
- **자유 텍스트 대상 해석**(채팅 요청 한정): 채팅으로 시작된 분석은 대상을 레이블이 아니라
  산문으로 지목하므로 namespace/pod/workload 없이 도착합니다. 그래서 스코프가 있는 수집기가
  전부 자기를 건너뛰고, 애초에 볼 수도 없던 증거가 없다며 abstain했습니다. 요청에 대상이
  **전혀** 없을 때에 한해, plan 단계가 운영자 문장에서 후보 이름을 뽑아 라이브
  deployment/statefulset/daemonset으로 검증합니다(사람이 타이핑하는 이름은 이들의
  `metadata.name`이고, pod 이름에는 생성된 접미사가 붙습니다). 매칭은 하이픈 경계에
  앵커되어 `thanos-receive`는 `runai-backend-thanos-receive`에 매치되지만
  `receiver-gateway`에는 매치되지 않으며, 후보는 구체적인 것부터 시도합니다. 워크로드 2개에
  매치되거나 하나도 매치되지 않으면 대상 없음으로 둡니다 — 스코프 없는 실행은 현상 유지지만,
  잘못된 대상은 모든 수집기를 확신에 찬 채 엉뚱한 서비스로 보냅니다. 구조적 identity가 항상
  우선합니다.
- **이미 시도한 조치**: 플래너 LLM이 운영자 문장에서 `attempted_actions`("메모리를 올렸는데도
  …")도 함께 반환하고 plan이 이를 싣습니다. 효과가 없던 조치는 **반증이 아니라 단서**이므로,
  그 조치가 겨냥한 family는 후보로 남고 왜 유지되지 않았는지 설명하도록 지시합니다. 이 주장은
  증거 텍스트에 넣지 않습니다 — 클러스터가 보고한 것이 아니라 운영자가 말한 것이기 때문입니다.

## 2. Parallel evidence collectors (7)

각 수집기(collector)는 하나의 도메인을 담당하며 `CollectorResult`(요약 + `artifacts`)를
반환합니다. `asyncio.gather`를 통해 동시에 실행됩니다.

| Collector | Owns |
|---|---|
| **runai** | Run:ai 워크로드/프로젝트/큐/쿼터/버전 컨텍스트(선택적으로 [공식 Run:ai MCP 서비스](#run-ai-mcp-service)의 집중된 읽기 전용 16개 도구 세트 경유) |
| **kubernetes** | 워크로드 파드/이벤트, Run:ai 컨트롤 플레인 파드 상태, 노드 컨디션, 스케줄링 차단 요인; 거부 목록(denylist)으로 게이트되는 선택적 읽기 전용 pod-exec |
| **prometheus** | 큐/프로젝트 GPU 메트릭, 대기/재시작/리소스 신호 |
| **loki** | 워크로드 로그 + `runai`/`runai-backend` 컨트롤 플레인 로그 |
| **postgres** | RCA 스토어 상태: pgvector, 임베딩(embedding), 피드백, 영속화 |
| **system** | Kubernetes 아래 노드 인프라 — dmesg/journalctl/syslog, NVIDIA XID/NVRM/OOM/MCE, 노드별 DaemonSet을 통한 InfiniBand HCA/포트 상태(`ibstat`) |
| **change** | *"무엇이 바뀌었나?"* — 최근 업데이트된 컨트롤러, 신규/삭제 중인 파드, 노드 컨디션 전이, 최근 이벤트 |

수집기 상한은 넉넉하여(각 120초) 증거가 깊습니다. 느린 수집기 하나가 있어도 여전히 `unavailable`로
우아하게 실패합니다. 민감한 값은 증거가 수집기를 떠나기 전에 마스킹(masking)됩니다
(`agent/app/masking.py`).

### 증거 시간, 범위, 전송 규칙

- 수집 시간 창은 발생 5분 전부터 해결 5분 후까지이며 firing 알림은 15분으로 제한됩니다.
  해결 후 에필로그는 문맥으로 남지만, Postgres, Change, System, Loki의 인과 승격은 해결 시각에 끝납니다(모두 하나의 `causal_evidence_time_range`를 공유).
- Kubernetes는 가장 비정상적이고 시간 관련성이 높으며 시간순으로 정렬된 Pod와 Event 5개를
  누락 수와 함께 유지하고, Warning 집계와 Normal `Preempted` workload/PodGroup 이벤트를
  보존하며, 노드 cordon/taint 상태를 포함합니다.
  Run:ai CRD 페이지네이션은 최대 3페이지까지 따르고 kind별 실패를 노출합니다. 과거 로그는 direct
  요청이 실제로 `sinceTime`을 적용한 경우에만 가장 오래된 라인을 유지하며, MCP tail은 최신 라인을 유지합니다.
  Cordon된(`SchedulingDisabled`) 노드는 범위가 지정된 cordon 아티팩트로 수집되며, live unschedulable
  증상이 실제로 있을 때만 unschedulable Pod의 근본 원인으로 승격될 수 있습니다. 증상이 해결된 뒤에는
  낮은 신뢰도로 유지됩니다.
- Loki는 전체 반환 라인으로 범위를 검증하고 여러 stream을 최신 항목부터 round-robin 샘플링합니다.
  Prometheus는 요청 시간 창에 맞춰 range-query step을 조정하고(약 1,000 포인트까지), 레이블 값을
  이스케이프하며 RFC3339 및 epoch 초/밀리초 sample timestamp를 허용합니다. 비어 있는 native
  Prometheus 결과는 범위가 확인된 부재일 수 있지만 MCP/proxy 빈 결과는 문맥입니다.
- Run:ai 현재 상태의 존재는 인시던트 시점 증명이 아닙니다. `present/scoped`에는 payload 안의
  시간 창 내 타임스탬프가 필요합니다. firing 알림에서는 immutable workload-ID 404만 범위가 확인된
  부재를 수립하며, 이름 기반 project/queue 404는 문맥으로 남습니다. 부분 MCP snapshot은 보존하고
  실패하거나 명시적으로 비어 있는 동등 항목에 direct 보완을 수행합니다. queue 레이블 알림은 direct
  queue 조회도 한 번 수행하며, 공백은 `runai.queue_scope`로 드러납니다.
- Run:ai 컨트롤 플레인 Postgres 읽기는 UTC를 고정하고 naive audit timestamp의 UTC 가정을
  공개합니다. 개별 audit-table 실패, 발견 제한, 이름이 표시된 컨트롤 플레인 연결 실패는 다른 수집
  증거를 지우지 않고 계속 보입니다.
- System의 `nvidia-smi`/`nvlink` 스냅샷 소스는 head-slice되어(`Attached GPUs : N`을
  포착) non-zero 카운터나 Xid/inactive-link 라인이 있어야만 매칭됩니다 — `0`/`N/A`/`None`/
  `Disabled` 같은 정상 `Label : Value` 값은 절대 fault로 인용되지 않습니다. 드라이버가
  열거한 GPU 수가 노드의 Kubernetes capacity보다 적으면 `node_gpu_inventory_deficit`
  아티팩트가 두 출처 값을 모두 담아 그 차이를 명시합니다(cordon/NotReady 노드는 마지막으로
  보고된 capacity를 유지하므로, 물리적으로 GPU가 빠졌을 때도 이 차이가 보입니다). `ibstat`도
  마찬가지로 항상 켜져 있는 `node_ib_inventory` 아티팩트(중립적인 CA/포트 사실)와, 포트가
  `Active`/`LinkUp`이 아닐 때만 나오는 `ib_port_degraded` 관찰을 냅니다. RDMA 리소스 단위는
  클러스터마다 다른 device-plugin 관례이므로 둘 다 capacity 부족을 주장하지 않습니다.

## 3. Deterministic follow-up

LLM과 무관하게, `k8s_followup` + `prometheus_followup`이 발견 사항을 추적합니다:
`Pending` 파드는 이벤트 → resourcequota → PVC → storageclass를 끌어오고, OOM/재시작은 도출된
PromQL을 끌어옵니다. 이는 LLM이 없을 때에도 수집을 반복적으로 유지합니다.

## 4. Per-collector autonomous drill-down

`agent/app/services/drilldown.py`(`ENABLE_AGENT_DRILLDOWN`, Helm 기본값 on). 기본 수집 이후,
**각 증거 에이전트는 자기 증거에 대해 자체적으로 적응형 LLM 루프를 실행**하고 자기 도메인 내에서
읽기 전용 후속 쿼리를 결정합니다.

**도구 스코핑은 프롬프트 기반이 아니라 구조적입니다** — 각 루프는 *오직* 자기 도메인의 도구
레지스트리만 받으므로, kubernetes 에이전트는 결코 Run:ai API를 호출할 수 없으며 그 반대도
마찬가지입니다:

| Agent | Drill-down tool | Read-only guarantee |
|---|---|---|
| kubernetes | `k8s_read` | 18종 허용 목록, GET/LIST 전용(시크릿 없음) |
| prometheus | `promql_query` | query 엔드포인트 전용 |
| loki | `logql_query` | range query 전용 |
| runai | 고정 `runai_*` view 15종(`runai_workload_summary`, `runai_workload_status`, …) | [공식 Run:ai MCP 서버](#run-ai-mcp-service)에 대한 읽기 전용 래퍼. 자유 인자 없음 — 모든 호출이 알림 자신의 workload/project/node로 사전 스코프됨 |
| postgres | `sql_select` | 단일 `SELECT`/`WITH`, READ ONLY 트랜잭션, 자동 `LIMIT 50` |
| *모든* 에이전트 | `knowledge_lookup`, `case_lookup`, `xid_lookup`, `component_checks`, `steps_lookup` | 온톨로지 우선 / 카탈로그 폴백 조회. 클러스터 호출 없음, 도메인 경계 넘지 않음, 답변은 결코 증거가 되지 않음 |

각 루프는 plan의 `operator_already_attempted` 목록도 함께 받습니다 — 그 조치가 실제로
적용됐는지 확인하고, 왜 문제가 살아남았는지 설명하는 쿼리를 우선하며, 다음 단계로 다시
제안하지 말라는 지시와 함께.

**모든 에이전트는 하나가 아니라 5개의 읽기 전용 지식 tool을 받습니다** — 쿼리를 세 번
돌린 뒤에 새 가설을 세운 에이전트가 plan 단계에서 가져온 지식에만 묶이지 않도록:

| Tool | 답하는 질문 | args |
|---|---|---|
| `knowledge_lookup` | "이 symptom/가설에 대해 이미 알려진 것이 무엇인가?" — 매칭되는 카탈로그 symptom + 운영자 승인 지식(family, 확인된 remediation), Run:ai known issue | `hypothesis` |
| `case_lookup` | "외부 벤더 서포트 케이스가 이 에러를 이미 본 적 있는가?" — family, mechanism, 시도한 것(효과 **없었던** 것 포함) | `text`(실제로 관측한 원문 에러/로그 텍스트) |
| `xid_lookup` | "이 NVIDIA XID는 무슨 뜻인가?" — 정체, 심각도, 해결 안내, 양방향 `leads_to` escalation chain | `xid` |
| `component_checks` | "이 플랫폼 컴포넌트는 무엇을 하며 어떻게 점검하는가?" — 목적, 실패 영향, 바로 실행 가능한 점검, 직접 의존성 | `component` |
| `steps_lookup` | "이 family의 다른 케이스는 어떻게 진단됐는가?" — 스레드 순서 그대로의 케이스 간 서포트 진단 step | `family`(닫힌 카탈로그), 선택적 `text` 필터 |

`knowledge_lookup`, `xid_lookup`, `component_checks`는 live TypeDB 온톨로지를 먼저
조회하고 실패하거나 TypeDB가 비활성화됐을 때 버전 관리되는 YAML 카탈로그로 폴백합니다.
`steps_lookup`은 그래프 전용입니다 — 케이스별 playbook step(`agent/ontology/
load_external_cases.py`)은 YAML로 미러링되지 않으므로 저하될 폴백 자체가 없습니다.
정상적으로 응답한 조회의 `source` 필드는 답이 어디서 왔는지 말해 줍니다: `ontology`(live
그래프), `catalog_fallback`(내장 YAML), `unavailable`(온톨로지도 폴백도 없음 —
TypeDB가 꺼져 있거나 도달 불가능할 때의 `steps_lookup`), `unresolved`(어떤 지식 소스도
참조하기 전에 로컬 이름 해석 자체가 실패 — 이름을 모르는 컴포넌트를 물은 `component_checks`).
`case_lookup`의 외부 케이스 검색은 TypeDB 전용이며 별도의 `source` 필드를 싣지 않습니다.
TypeDB가 꺼져 있거나 도달 불가능하거나 시간 초과되면 "no external support case matches
that text"라는 빈 결과로 조용히 저하됩니다.

`knowledge_lookup`은 랭커가 쓰는 것과 동일한 병합 맵 — 버전 관리되는 카탈로그 + 운영자
승인 런타임 지식 — 을 읽으므로, plan 작성 이후에 승인된 지식에도 도달합니다. 각 항목은
출처(`curated` / `learned` / `novel`)와 `matcher_only`를 함께 실어 보냅니다. novel
family는 보고할 root cause가 아니라 검증할 안내이기 때문입니다.

다섯 tool의 답변은 모두 의도적으로 **artifact를 만들지 않습니다** — 에이전트는 자신의
추론 루프 안에서 답을 보고 실행 기록은 `details.knowledge_lookups`에 남지만, 큐레이션
문구가 관측 증거 텍스트에 들어가면 시그니처 매처가 우리 카탈로그를 클러스터가 보고한
내용으로 되읽기 때문입니다.

postgres 에이전트는 `RUNAI_DB_DSN`이 설정되면 RCA 스토어뿐 아니라 **Run:ai 컨트롤 플레인
데이터베이스 자체**에 질의합니다(workloads/audit/authorization/… 스키마). 도구 설명은
[아키텍처 토폴로지](KNOWLEDGE-BASE.md)의 스키마 소유권으로 강화되므로, 루프는 어디를 봐야 할지
압니다.

에이전트 완료·반복 쿼리·분석 deadline까지 계속 진행하며, 사용 불가한 수집기와 구성되지 않은 데이터
소스는 건너뛰며, 결코 예외를 발생시키지 않습니다. 신뢰할 수 없는 로그/이벤트 텍스트가 이 루프에
공급되므로, [프롬프트 인젝션 가드](#safety-envelope)가 모든 결정에 함께 실립니다.

### Central investigation loop

수집기별 드릴다운과 구별됩니다: `agent/app/services/investigator.py`
(`ENABLE_INVESTIGATION_LOOP`, Helm 기본값 on)는 **교차 도메인 라우터**입니다. LLM이 다음에 어떤
수집기를 조사할지 결정하고, 동일한 18종 허용 목록에 걸쳐 임시(ad-hoc) 읽기 전용 Kubernetes 읽기를
실행할 수 있습니다. 기본값 `MAX_INVESTIGATION_STEPS=0`은 고정 agent-step 제한이 아니라 명시적
결론·중복/소진된 probe·전체 분석 deadline에 따른 의미적 완료를 뜻합니다. 종합은 항상 *모든* 수집기를
기다립니다 — 조기/부분 종합은 확신에 찬 그러나 잘못된 RCA를 만들 것입니다.

Kubernetes 진단 트리는 질문·점검·구조화된 읽기 전용 probe뿐 아니라 해석 노트, 피해야 할 행동, 명시적
반증 조건까지 evidence agent에 투영됩니다. 모든 종단 분기에는 신뢰도 경계도 있으므로, agent는
runbook을 정답 목록처럼 따르지 않고 모순되는 live evidence가 나타나면 그럴듯한 분기를 떠날 수 있습니다.

## 5. Signature matching + BM25 recall + ranking

검색 진입점은 거친 패밀리 랭커가 아니라 **세분화된 시그니처 매칭(signature match)**입니다:

1. **내장 알림**을 이름으로 매칭(`runai_alerts_catalog.yaml`).
2. **known issue(알려진 이슈)**를 키워드 시그니처로 매칭, 버전 인지
   (`runai_known_issues.yaml` — 실행 중인 버전에서 수정된 이슈는 제외).
3. **실패 모드 증상**을 **모든** 패밀리에 걸쳐 키워드로 매칭(`failure_modes.yaml`).
4. 증거 + 알림 자체 텍스트에서 추출한 **NVIDIA XID** 코드.

큐레이션된 부분 문자열이 매칭되지 않으면, 보수적인 **BM25 + 동의어** 패스
(`agent/app/bm25.py`, 표준 라이브러리)가 어휘 변형을 복구합니다(`evicted` → `preempt`/
`reclaim`, `job` → `workload`). 이는 알림 텍스트만 질의하고, `matched_via: "bm25"`로 태그되며,
결코 원인을 헤드라인으로 올리지 않습니다 — 검증 패스가 여전히 반박할 수 있는 후보만 노출합니다.
카탈로그에 대해서는 [Knowledge Base](KNOWLEDGE-BASE.md)를 참조하십시오.

**랭킹**(`root_cause_ranking.py`, 규칙 R1–R6)은 후보의 *순서를 매기고* 신뢰도를 게이트하는
결정론적 단계이며, 검색 엔진이 아니고 그 점수도 확률이 아닙니다. 형식화된 관측은 고유 evidence
fact 하나당 한 번만 계산합니다(정식 collector `+2`, 보강 collector `+1`, collector당 최대 3개).
따라서 한 fact 안에 같은 뜻의 키워드가 여러 개 있어도 점수가 중복 상승하지 않습니다. 아직 typed
observation으로 이행하지 않은 레거시 결과만 상한이 있는 키워드 호환 경로를 사용합니다. 규칙,
토폴로지, lifecycle, feedback prior, live symptom ontology 보정은 `score_breakdown`에 별도로 남습니다.

Kubernetes container waiting/terminated `reason`은 collector가 구조화된
`observation.container_reason`으로 발행할 때 kubelet의 폐쇄된 vocabulary로 처리합니다.
랭커는 자유 텍스트 negation heuristic을 우회하고, 유지 관리되는 reason-to-family 표에 따라
토큰을 정확히 매칭합니다. 표에 없는 reason은 coverage warning으로 로그에 남습니다. 일반
로그, 이벤트, annotation의 자유 텍스트는 기존 호환 keyword 경로를 계속 사용합니다.

후보 정렬 순서는 **미해결 반증 없음 → 보정된 confidence → 독립 telemetry group 수 → 숫자 점수**입니다.
medium은 `2`부터이고, high는 점수 `5`와 독립 live source group 2개가 필요합니다(또는 확정적
`force_high` signature). scoped contradiction이 있으면 low로 제한하며, 정식 source가 unavailable이면
한 단계 하향합니다. 이후 `_promote_signature_cause`가 검증된 가장 구체적인 시그니처
(XID > known-issue > symptom > ranker)를 적용하고 evidence ID와 점수 진단을 보존합니다.

## 6. Self-check → re-analysis → verify

- **반박**(`self_check.refute_top_cause`): 회의적인 시니어 SRE 패스가 오직 eligible하고 해당
  family와 관련된 support/contradiction fact만 사용해 최상위 원인을 반박하고 confidence를 보정하며,
  한 줄 주의 사항 + 다음 점검을 작성합니다. self-check는 랭커의 숫자 점수를 계산하거나 사용하지
  않습니다.
- **재분석**: 반박되거나 증거가 부족하면 차선의 가설을 대상으로 의미적 완료 또는 분석 deadline까지
  재분석합니다. `MAX_REANALYSIS_STEPS=0`이 기본이며, 양수 값은 레거시 호환용입니다.
  `analyze()`에 재진입하지 않도록 강하게 가드됩니다.
- **매칭 검증**(`verify_matches`): 회의적인 패스가 증거가 실제로 뒷받침하지 않는 키워드/시그니처
  매칭(known issue, 증상, XID)을 제거합니다.

시그니처 검증으로 헤드라인이 바뀌면 synthesis 전에 새 후보를 다시 self-check합니다. 현재 선두가
반박되고 이미 랭크된 대안도 같은 검사를 통과하지 못하면, 반박된 원인을 종합하지 않고
`insufficient_evidence`를 반환합니다.

## 7. Ontology enrichment

**오케스트레이터**는 선택적 TypeDB 지식 그래프(병렬 수집기가 아님)를 참조합니다 —
[Knowledge Base](KNOWLEDGE-BASE.md)를 참조하십시오:

- `enrich()`: 노드 **blast radius(영향 범위)**(알림이 발생한 노드를 공유하는 워크로드 수)와
  저장된 RCA를 가진 **동일 알림의 이전 인시던트**.
- `graph_remediation()`: symptom 기반 `_KNOWLEDGE_QUERY`(승격된
  큐레이션 symptom. `confirmed:{alert_name}` 승격은 폐기·비활성), `fixes_for_xid`, 그리고 역방향 `leads_to`
  **근본 XID 체인**(하류 증상이 아니라 기원을 수정).

TypeDB가 꺼져 있거나 도달 불가능할 때는 빈 값으로 저하되며, 결코 예외를 발생시키지 않습니다.

## 8. Synthesis

`_detail_from`은 결정론적 리포트를 구성합니다 — **Problem → Root Cause →
Recommended Actions → Appendix** — 운영자(또는 Word 내보내기)가 읽는 약 1페이지 분량의
문서입니다. 이 리포트의 모든 결론은 코드가 만들며, LLM이 리포트를 저작하지 않습니다.

**관측된 설정.** 모든 메커니즘 문장은 *무엇이* 실패했는지를 답합니다. 운영자의 다음 질문은 항상
"그것이 어떤 설정이었는지"입니다. 그래서 각 typed artifact가 자기가 타이핑한 대상의 설정을 함께
싣고, Root Cause는 *eligible*한 artifact에서 대상별로 한 줄씩 렌더합니다. family별 분기 테이블이
필요 없고, 관측 없이 서술되는 값도 없습니다.

| 줄 | 출처 artifact | 담는 값 |
| --- | --- | --- |
| `현재 설정 (main)` | `kubernetes_container_lifecycle` | memory/cpu/GPU limit·request, image |
| `프로브 설정 (main)` | `kubernetes_warning_events` + Pod spec | handler와 임계값. eligible한 `Unhealthy` 이벤트가 있을 때만 |
| `요청 리소스` | `kubernetes_pod_scheduling` | 컨테이너별 요청량, `nodeSelector`, `schedulerName`, Run:ai 자체 GPU 집계 |
| `프로젝트 quota` | `runai_queue_quota` | 요청 대비 quota, 상한, over-quota 가중치 |
| `스토리지 클레임` | `kubernetes_storage_claim` | 요청 용량, storageClass, access mode, phase |
| `노드 GPU` | `kubernetes_node_gpu_resources` | 여유/allocatable과 기존 Pod 점유량 |
| `노드 용량` | `kubernetes_node_condition` | 노드의 allocatable 용량 |

두 가지 실패는 책임 있는 *설정*이 증거와 다른 artifact에 있습니다. 그래서 eligible 순회 뒤에
해석하며 절대 그 결과를 덮어쓰지 않습니다. not-Ready 컨테이너는 인과적 컨테이너 state가 없고
(kubelet이 `Unhealthy` 이벤트로 보고), Bound 클레임은 그것이 가리키는 볼륨의 attach가 실패했을 때
클레임 자체가 막힌 것이 아닙니다. 두 경우 모두 이벤트가 eligible 증거여야 하며, 설정은 정체성이
검증된 spec에서 읽습니다.

**조치에는 placeholder가 아니라 값이 담깁니다.** 큐레이션 조치는 placeholder로 작성된 family 수준
지식이며, 번호 목록이 해당 런의 관측값을 치환합니다([KNOWLEDGE-BASE.md](KNOWLEDGE-BASE.md) 참고).
카탈로그가 숫자를 담을 수 없는 부분은 리포트가 도출합니다. 알려진 limit에서 OOMKilled된 컨테이너는
옛 limit을 새 request로(실제 사용량 근거), 옛 limit의 2배를 새 상한으로 제시하고 실행 가능한 명령을
함께 냅니다 — kubectl이 패치할 수 있는 kind에만 `kubectl set resources`를, Run:ai나 Grove 워크로드처럼
CRD가 소유한 Pod에는 소유자에 대한 `kubectl edit`을 사용합니다.

**운영자 요청**은 자체 블록을 갖고, 이미 시도했다고 말한 조치를 그 바로 아래 — 추천 조치보다
위에 — 나열합니다. 조치부터 스크롤해 내려간 독자가 이미 제외된 단계를 먼저 알도록 하기
위해서입니다. 이미 시도한 조치를 다시 말하는 추천은 **삭제가 아니라 표시**합니다. "메모리를
올렸다"가 메모리 경로를 틀리게 만드는 것은 아니며(잘못된 컨테이너에 적용됐거나 재시작으로
되돌아갔을 수 있음), 그 단계를 지워버리면 그 가능성이 숨겨집니다.

**매칭된 지원 사례가 일반 가이드 블록 맨 앞에** 자체 제목으로 옵니다. 시그니처가 매칭된 벤더
사례는 증거 없는 실행이 줄 수 있는 가장 밀도 높은 정보 — 정확히 이 시그니처를 겪은 실제 배포,
무엇을 시도했고 무엇이 실제로 도움이 됐는지 — 인데, 일반 점검 12개 중 한 줄로 놓이면 채움글로
읽혔습니다. 여전히 history로 표시하며 이번 실행의 확정 원인은 아닙니다.

`language=ko`이고 LLM이 구성된 경우 `_translate_report_lines_ko`가 **가장 마지막에** 실행됩니다 —
Self-Check, 추가 확인 요청, 일반 가이드 블록까지 덧붙인 뒤 — 리포트를 *줄 단위로* 한국어화합니다.
한글이 없고 실제 산문인 줄만 전송되며, 헤딩·펜스 블록(Alert Labels JSON 포함)·명령어·식별자만 있는
줄은 프로세스를 벗어나지 않습니다. 따라서 번역이 결론을 바꾸거나 섹션을 누락시키거나 문서 순서를
바꾸는 일이 구조적으로 불가능합니다. 줄은 약 2,000자 단위(`_TRANSLATION_BATCH_CHARS`)로 나눠
보내고 `max_tokens`도 배치 크기에 맞춰 잡습니다 — 긴 리포트를 한 번에 번역하던 방식이 completion
cap에 걸려 리포트가 들어갈 때보다 짧게 돌아오곤 했기 때문입니다. 응답은 보호 구간이 한 글자도 바뀌지 않은 줄만 채택합니다 — 백틱 구간,
겹따옴표 구간, 그리고 `CreateContainerConfigError`·`secretKeyRef`·`nvidia.com/gpu` 같은 API
용어 — 일반 영어 문장은 그대로 번역됩니다. 한 배치가 실패해도 성공한 배치는 유지하며, 번역되지 않은 줄이 하나라도 남으면
`synthesis_failed` + `analysis_quality=degraded`로 표시합니다. `context.synthesis`에는 `status`,
`duration_seconds`, `model`, `max_tokens`가 담깁니다.

**Troubleshooting Playbook** 섹션은 연루된 모든 플랫폼 컴포넌트에 대해 그 실패 영향, BFS
**의존성 점검 순서**(예: `cluster-sync → status-updater → runai-backend-traefik`), 그리고 바로
실행 가능한 `kubectl` 점검을 [아키텍처 토폴로지](KNOWLEDGE-BASE.md)에서 가져와 덧붙입니다.

**run이 끝내 family를 확정하지 못하면** (`insufficient_evidence`), Troubleshooting
Playbook과 "### Knowledge Base (Ontology)" 부록 모두 침묵하거나 과신하는 대신 명시적으로
헤지된 형태로 전환됩니다: 랭커가 채택하지 않은 cross-family symptom 매치를 최대 2개까지
`(지식 매칭 — 미확정)`으로 태그해 보여 주고, 여기에 가장 잘 매칭된 외부 서포트 케이스
하나를 더합니다 — 그 케이스가 기록한 결과에서 뽑은 "당시 유효했던 조치" / "당시 효과
없던 조치", 또는 기록된 fix가 없을 때는 "당시 지원팀의 진단 수순 참고 가능"이라는
안내입니다. 헤더는 이 항목들이 축적된 지식과 과거 사례에 근거한 참고 조치일 뿐 확정
진단이 아니라고 명시적으로 밝힙니다. 랭킹 자체는 건드리지 않습니다 — 헤드라인 원인이
되지 못한 family에 대해 playbook이 무엇을 렌더링하는지만 바뀝니다.

**클러스터 증거가 없는 chat-adhoc 질문**은 위의 헤지된 부록보다 더 직접적인 답을
받습니다. RCA 버튼으로 던진 질문이 합성 chat-adhoc 알림(그 summary가 곧 운영자의
질문 문장)을 만들고 run이 적격 증거 없이 끝나면, `_chat_adhoc_knowledge_ladder_lines`가
섹션 1~3(Problem / Root Cause / Recommended Actions)을 결정론적 지식 ladder로 통째로
교체합니다: XID 카탈로그(드릴다운 툴을 통한 TypeDB 우선, YAML `catalog_fallback`) →
정확히 일치하는 알려진 이슈 → 전체 family를 아우르는 정확히 일치하는 지식베이스 증상 →
외부 서포트 케이스, 그리고 — 이들이 모두 비어 있을 때만 — 적격 BM25 최근접 증상과
planner의 닫힌 카탈로그 family를 "다음으로 해석됨" 리드로 덧붙입니다. 이 ladder에는
LLM 호출이 전혀 없습니다. 응답에는 `context["answer_mode"] = "knowledge_only"`가
실리고, `root_cause_family`는 `insufficient_evidence`로 유지되며 harness 판정도
그대로입니다. 프런트엔드는 이 답변이 지식 베이스 안내이지 현재 클러스터에 대한 진단이
아니라는 배너를 표시하고, 백엔드는 운영자가 나중에 승인하더라도 이런 run을 유사
인시던트 메모리와 지식 승격에서 제외합니다(`upsertMemoryLocked`와
`knowledgePromotionGates`의 `answer_mode` 배제). Seed honesty는 질문 문장 자체를 증거
경로 밖에 둡니다: chat-adhoc run에서는 질문에서 파생된 summary를 alert-signature
텍스트에서 제외하므로, "XID48"을 물어봤다고 해서 그 자체가 alertmanager 발신 시그니처
매치를 만들어 낼 수 없습니다.

## 9. Runtime harness

Synthesis 뒤에는 응답 경계 하네스가 artifact에 `E01`, `E02` ID를 부여하고 root-cause
claim ledger와 최종 보고서를 검사합니다. high confidence 원인에는 두 개의 독립 live source
또는 확정 signature가 필요하며, 주요 주장은 현재 run evidence를 인용해야 합니다. 변경성 조치에는
앞선 안전 guardrail도 필요합니다. 하네스는 `MAX_RCA_REPAIR_ATTEMPTS`(기본 3)만큼 결정론적으로
수정하고, hard gate가 남으면 추측 대신 `insufficient_evidence`를 반환합니다. TypeDB 과거 사례는
문맥일 뿐 live-evidence gate를 통과시키지 못합니다. [평가](EVALUATION.md)를 참고하세요.

하네스의 가중 0–100 품질 점수는 원인 순서를 정하는 랭커 점수와 별개입니다.
`confidence_diagnostics`는 두 체계를 함께 보존합니다: 랭커의 세부 증감과 source gate,
self-check 전후 confidence, 그리고 harness 점수·hard gate·수정 횟수·harness 전후 confidence입니다.

## Evidence presentation

모든 아티팩트는 운영자가 한눈에 읽을 수 있도록 구성됩니다:

- **`title`** — 사람이 읽는 카드 이름(`파드 조회`, `메트릭 조회 (PromQL)`, `DB 조회 (SQL)`).
- **`query`** — 재실행할 *실제* 명령: `kubectl get pods t-0 -n runai`, 원시 PromQL/LogQL/SQL,
  `MCP get_workload_status {…}` — 결코 내부 파라미터 덤프가 아닙니다.
- **`highlights`** — 결과에서 추출한 문제 신호(`salient_markers`: `CrashLoopBackOff`, `Xid 79`,
  `no space left`, … — 문자열 리프만 스캔하며, 결코 JSON 키가 아님). Frontend는 이를 빨간색으로
  표시하여 상용구보다 발견 사항이 먼저 읽히도록 합니다.

실패한 probe나 에이전트 자신이 잘못 만든 드릴다운 쿼리처럼, 에이전트 스스로 만든 노이즈만
보여줄 카드는 evidence trail에 표시하지 않습니다.

## Safety envelope

- **구조적으로 읽기 전용**: 수집기와 드릴다운 도구는 읽기만 합니다. Kubernetes 읽기는 종별 허용
  목록, pod-exec는 거부 목록(denylist)으로 게이트되어 상태를 바꾸는 명령, shell/인터프리터,
  shell 메타문자를 차단하고 shell 없이 단일 argv만 실행합니다. Run:ai 드릴다운은 알림 범위로
  사전 스코프된 공식 MCP 읽기 view 고정 세트를 거치고(수집기의 직접 REST 읽기는 GET 전용),
  SQL은 READ ONLY 트랜잭션의 `SELECT`.
- **프롬프트 인젝션 가드**(`agent/app/llm.py`): 수집된 텍스트(로그, 이벤트, 알림 어노테이션)는
  클러스터 쓰기가 가능하므로, 임베디드 명령을 데이터로 선언하는 가드가 **모든** LLM 시스템
  프롬프트에 덧붙여집니다. `operator_prompt`가 유일하게 의도된 명령 채널입니다.
- **마스킹(masking)**(`agent/app/masking.py`): JWT, 베어러 토큰, 시크릿, 커스텀
  `MASKING_REGEX_LIST_JSON` 패턴은 증거가 수집기를 떠나거나 LLM에 도달하기 전에 편집(redact)
  됩니다. password/credential 유형 키는 항상 마스킹하고, token/secret 문구는 자격 증명 형태의
  값만 마스킹하므로 `connection refused` 같은 진단 문구는 남습니다. `sha256:` 이미지 digest는
  보존되며, salient signal 추출은 저장할 증거를 마스킹하기 전에 수행됩니다.

## Run:ai MCP Service

`RUNAI_MCP_URL`이 설정되면, runai 수집기와 runai 드릴다운 에이전트는 NVIDIA의 공식
Run:ai MCP 서버를 사용합니다. 이 서버는 `/mcp`의 OIDC 보호 스트리머블 HTTP를 통해
집중된 읽기 전용 16개 도구 세트를 제공합니다. Helm 차트는 이를 공유 ClusterIP 서비스로
배포하고 기본적으로 이 URL을 설정합니다(`runaiMcp.enabled: true`). MCP 실패 시에는
Run:ai 직접 HTTP 읽기로 폴백합니다 — 엄격히 부가적이며, 결코 분석을 깨뜨리지 않습니다.

## Configuration

모든 환경 변수는 [Configuration Reference](CONFIGURATION.md)를 참조하십시오. 파이프라인 스위치:
`ENABLE_INVESTIGATION_LOOP`, `MAX_INVESTIGATION_STEPS`, `ENABLE_AGENT_DRILLDOWN`,
`RUNAI_DB_DSN`, `ANALYSIS_DEADLINE_SECONDS`,
`ENABLE_RCA_OUTPUT_HARNESS`, `MAX_RCA_REPAIR_ATTEMPTS`, `RCA_HARNESS_PASS_SCORE`,
`RUNAI_MCP_URL`.
