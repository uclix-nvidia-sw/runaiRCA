# 지식 소비 계층 실측 검토 — INC-1782967135070090009-000003 (Ready GPUs)

작성: 2026-08-11 · 대상 런: `ANL-1786413067600041067-000001` (2026-08-11 01:51 UTC, v0.1.112 계열 배포에서 수동 재분석) · 결론: `insufficient_evidence` (quality: degraded)

## 한눈에 보는 결론

PR #106("에이전트가 조사 중 온톨로지를 직접 조회")이 머지·배포된 뒤 처음으로 새 코드가 실제 인시던트를 분석한 사례를 전수 검토했다.

- **플랜 계층의 지식 소비는 의도대로 작동했다.** 컴포넌트 정체성(nvidia-device-plugin-daemonset)으로 에러 문자열 없이 `gpu_hardware_error` 가설을 세웠고, 드릴다운이 그 가설대로 Xid/디바이스 플러그인 사냥 쿼리를 11회 돌렸으며, TypeDB도 살아서 과거 사고 조회에 응답했다.
- **이번 릴리스의 핵심 2가지는 이 인시던트에서 효과가 0이었다.**
  - ① 미드루프 지식 툴(5종): 호출됐는지조차 **확인할 방법이 없다** (영수증이 에이전트 프로세스 밖으로 나가지 않고, 성공 호출은 로그도 남기지 않는다).
  - ② 증거불충분 헤지 블록: 입력이 키워드 매치 전용이라, 에러 문자열이 아예 없는 이런 메트릭 알림에서는 **구조적으로 굶주린다** — 정작 손에 있던 `gpu_hardware_error` 가설은 헤지에 공급되지 않는다.
- 그 외 리포트 품질 문제 2건(이미 실행한 쿼리를 운영자에게 재요청, 약한 유사도 후보를 "재발"로 표현)과 scope 문제 1건을 확인했다.

아래 개선안 6건 중 **P1 3건은 각각 국소 변경이라 한 브랜치로 묶어 작은 PR이 가능**하다.

---

## 1. 이 인시던트에서 실제로 일어난 일

### 알림의 실체

- Grafana 자동생성 알림 `Ready GPUs` (`grafana_folder: Runai/overview-dashboards`, 패널 82).
- 라벨에 **node / namespace / pod가 전혀 없다.** `__value_string__`조차 `labels={} value=8 → C=1` — 룰 자체가 클러스터 합계로 집계돼 있어 payload만으로는 어느 노드가 문제인지 복원이 불가능하다.
- 유일한 대상 단서는 알림 그룹핑이 모은 occurrence pod 이름 2개(`nvidia-device-plugin-daemonset-*`)였고, 여기서 컴포넌트 정체성이 발동했다.

### 의도대로 작동한 것 (✅)

| 항목 | 근거 |
|---|---|
| 컴포넌트 정체성 → 가설 | plan Approach가 "알림 대상은 플랫폼 컴포넌트 'nvidia-device-plugin-daemonset'… XidCriticalError" 명시, H1=`gpu_hardware_error` |
| 드릴다운 적극성 | LLM 39콜, 7개 에이전트 전부 드릴다운 실행. loki만 Xid/디바이스플러그인 사냥 11쿼리(E22–E32), k8s는 daemonset·pod 직접 조회(E13–E18) |
| Run:ai 공식 MCP 15툴 | E48–E55: `get_cluster_physical_inventory`, `get_cluster_infrastructure_health`, `get_cluster_metrics` 등 — 전부 사전 스코프 호출 |
| TypeDB 가동 | KB 부록에 그래프 prior-incident 2건 조회 성공 (`ontology_reasoning`은 workload 없음으로 빈 값 — 정상) |
| 리포트 정직성 | 원인 조작 없이 `insufficient_evidence` + 구체적 추가 확인 요청 4건, 한국어 synthesis 정상 |

### 의도와 어긋난 것 (❌)

| # | 현상 | 실측 근거 |
|---|---|---|
| A | 지식 툴 호출 여부 판별 불가 | run JSON 1.25MB 전체에 `knowledge_lookups`/`source: ontology` 등 흔적 0. 원인: 영수증은 `result.details["knowledge_lookups"]`에 쓰이지만 **pipeline이 collector details를 response로 승격하는 코드가 없다**(write-only). 성공 호출은 warning-only 로깅 관례상 로그도 없음 |
| B | 39콜 동안 지식 툴 미사용 정황 | Xid 가설을 세워놓고 `xid_lookup`·`knowledge_lookup` 무호출로 보임. 드릴다운 시스템 프롬프트의 "How to work" 수칙에 지식 툴 사용 시점 언급이 전무하고, "모든 쿼리는 특정 아이디어를 검증해야 한다" 수칙이 지식 조회를 구조적으로 배제 |
| C | 헤지 블록 0줄 | 플레이북·KB 모두 "대상/창 범위 관측이 제공될 때까지 보류" 일반 문구로 추락. `_insufficient_evidence_playbook_lines(symptom_matches, case_cards)`는 키워드 매치 2종만 소비 — 이 알림은 에러 텍스트가 없어 둘 다 빈 값, H1 family는 입력에 없음 |
| D | 이미 실행한 쿼리를 운영자에게 재요청 | 추가 확인 요청: "LOKI로 XidCriticalError 쿼리 결과를 제공해 주세요" ← E24/E25로 **이미 실행했고 공란**이었다 |
| E | 약한 유사도 후보를 "재발"로 표현 | "이 알림은 이전 2건의 사고에서 재발했습니다" — 인용 2건은 다른 alertname(KubeContainerWaiting / Pod NotReady), 유사도 0.18의 임베딩 후보. 렌더 라인(`This alert recurred in N prior incident(s)`)이 same-alert 매치와 similarity 시드를 구분하지 않음 |
| F | scope 미검증 강등 15/61 | "no observation ever reached present+scoped". 노드 라벨이 없어 전 에이전트가 클러스터 전역 스캔 — 그런데 runai 인벤토리(E52)에 노드별 GPU 수가 이미 있었다. "8→1로 떨어진 노드"를 찾아 scope로 승격할 재료를 손에 들고도 쓰지 않았다 |

환경 이슈(코드 아님): Loki가 MCP·직접 API 모두 502, k8s MCP는 self-signed cert로 직접 폴백. 별도 인프라 점검 필요.

---

## 2. 개선안 — 쉽게, 구체적으로

### P1-A. 지식 툴 영수증을 밖으로 내보내기 (관측성)

- **무엇을**: 드릴다운이 쌓는 영수증을 응답으로 승격 — `response.context["knowledge_consultations"]` = `[{agent, tool, query(≤120자), source, hits}]`, 전체 ≤20행 bound.
- **어디를**: `pipeline.py`의 response 조립부(다른 context 키들이 세팅되는 곳)에서 `state.results[*].details["knowledge_lookups"]`를 수집·축약. `response_budget.py`의 `_PROTECTED_CONTEXT_KEYS`에 추가(작은 필드라 안전).
- **왜 지금**: 이 필드가 없으면 B의 진위(호출 0인지, 호출됐는데 안 보이는 건지)를 영원히 판별할 수 없다. 문서의 "run keeps a receipt" 서술과 프로덕션 실체도 어긋나 있다.
- **검증**: 배포 후 아무 인시던트나 재분석 → run metadata에 `knowledge_consultations` 존재 확인. (프런트 배지는 후속으로 분리 가능)

### P1-B. 드릴다운 프롬프트에 "지식을 먼저 물어라" 수칙 1개 추가 (salience)

- **무엇을**: `drilldown.py` `_system_prompt`의 How-to-work에 불릿 1개:
  - "새 가설을 세우거나 바꿀 때, 먼저 knowledge_lookup(가설)·case_lookup(관측한 에러 원문)·xid_lookup(XID 번호)·component_checks(플랫폼 컴포넌트)·steps_lookup(family)로 이미 알려진 것을 1회 확인하라. 답은 검증할 안내이지 증거가 아니다."
- **왜**: 현재 수칙은 증거 쿼리만 정의해서, 수칙을 잘 따르는 LLM일수록 지식 툴을 안 부른다. 툴 설명만으로는 행동 계약을 못 이긴다.
- **검증**: P1-A 배포 후 이 인시던트 재분석 → `knowledge_consultations`에 k8s/loki 에이전트의 호출 ≥1 확인.

### P1-C. 헤지 블록에 세 번째 입력 추가 — family lead (설계 갭)

- **무엇을**: `_insufficient_evidence_playbook_lines`가 키워드 매치 2종 외에, **랭킹된 family 후보(컴포넌트 정체성·plan 가설 유래)**도 소비. 매치가 0이어도 family lead가 있으면 그 family의 참고 조치 ≤3을 `(컴포넌트 정체성 기반 — 미확정)` 태그로 렌더. 기존 헤지 헤더·어휘 재사용.
- **왜**: "증거불충분이어도 쌓아놓은 지식 기반 대처법이 나왔으면 좋겠다"는 원래 요구가, 에러 문자열 없는 메트릭 알림(이번 케이스)에서는 지금 구조상 절대 발동하지 않는다. 이번 런은 `gpu_hardware_error` lead를 쥐고도 "playbook 보류"만 냈다.
- **검증**: 이 인시던트 재분석 → 권장 조치에 gpu_hardware_error 계열 참고 조치가 헤지 태그와 함께 렌더.

### P2-D. 추가 확인 요청을 실행 이력과 대조

- **무엇을**: follow-up 질문 생성 프롬프트에 "이 런이 이미 실행한 드릴다운 쿼리 목록"을 주입하고, 이미 실행되어 공란이었던 항목은 "당시 창에서는 비어 있었으니 재발 시 캡처" 형태로 바꾸도록 지시.
- **왜**: 방금 실행해서 공란이었던 쿼리를 운영자에게 다시 요청하면 리포트 신뢰가 깎인다.

### P2-E. 수량형(합계) 알림의 scope 자가 유도

- **무엇을**: plan 단계 scope 재해석 확장 — 알림에 node/namespace가 없고 값이 수량형이면, prometheus/runai로 차원별 diff 1회(예: 노드별 ready-GPU 수의 창 전후 비교)를 돌려 떨어진 차원을 `target.node`로 승격(유도 근거 라벨 포함). 기존 live pod/node resolution의 자연스러운 확장.
- **왜**: scope 미검증 강등 15/61의 뿌리. 재료(노드별 인벤토리)는 이미 수집되고 있었다.

### P2-F. prior 유래에 따라 "재발" 문구 분기

- **무엇을**: `pipeline.py:7730`의 recurrence 라인을 prior 항목의 유래로 분기 — same-alert 그래프 매치만 "재발", similarity 시드는 "관련 가능성이 있는 과거 사고(참고)"로.
- **왜**: 유사도 0.18짜리 다른 알림 사고 2건을 "이 알림이 재발했다"로 단정하는 것은 증거 정직성 원칙과 어긋난다.

### 운영 체크리스트 (코드 아님)

1. Loki 게이트웨이 502 — MCP·직접 API 모두 실패했다. 인그레스/게이트웨이 상태 점검.
2. k8s MCP self-signed cert 폴백 — agent의 CA 신뢰 설정 확인.
3. Grafana "Ready GPUs" 룰에 `by (node)` 차원 추가 권장 — 라벨에 node가 실리면 P2-E 없이도 scope가 즉시 풀리고, 이 계열 알림 전체의 분석 품질이 오른다.

---

## 3. 우선순위와 예상 효과

| 순위 | 항목 | 변경 규모 | 효과 |
|---|---|---|---|
| P1-A | 영수증 승격 | pipeline 1곳 + budget 1줄 | 기능 작동 여부가 처음으로 보이게 됨 |
| P1-B | 프롬프트 수칙 1줄 | drilldown 1곳 | 지식 툴이 실제로 소비되기 시작 |
| P1-C | 헤지 family lead | pipeline 1함수 | 무텍스트 알림에서도 지식 기반 참고 조치 발동 |
| P2-D/E/F | 리포트 정합·scope | 각 1곳 | 운영자 신뢰·scope 게이트 해소 |

P1 3건 + P2-F는 서로 독립적인 국소 변경이라 한 PR로 묶기 좋다. P2-E는 plan 단계 설계가 필요해 별도 진행 권장.

검증 원칙: 세 P1 모두 "이 인시던트(INC-…000003)를 재분석해서 결과물에 나타나는지"가 최종 판정 기준이다 — 단위 테스트만으로 닫지 않는다.
