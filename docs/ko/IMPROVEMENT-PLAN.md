# 개선 계획

> **관점:** 리뷰 후속 조치 — 이번에 바꾼 것과 남은 것.
> **이 문서에서 다루는 것:** 리뷰 점수 · 반영된 퀵윈과 기능 · 측정된 eval 결과 · 남은 로드맵.

1차 모의 심사에서 Run:AI RCA는 **66.7/100**을 받았고, 1차 수정 후 재심사에서는
**72.6/100**을 받았습니다. 남은 핵심 문제는 거대한 시스템 하나가 통째로 빠진 것이 아니라,
운영 도구를 매일 믿고 쓰게 만드는 작은 조각들이 부족하다는 점이었습니다.
CI 커버리지, 라이선스 명확성, eval taxonomy 드리프트, 일시적 LLM 실패 처리, 고정되지 않은
외부 소스, 토큰 비용 가시성, 인시던트 라이프사이클 제어가 주요 지적 사항이었습니다.

이번 리뷰 기준은 다음 관점으로 정리했습니다.

- **정확성과 eval 품질:** fixture label이 taxonomy와 맞아야 하며, RCA 분류기는 측정 가능한
  상태로 유지되어야 합니다.
- **신뢰성과 운영성:** 일시적인 LLM 오류에는 제한된 retry가 필요하고, backfill이 삭제된
  인시던트를 되살리면 안 되며, trash purge는 테스트 가능해야 합니다.
- **관측성과 비용 제어:** LLM 토큰 사용량은 에이전트에서 백엔드와 프런트엔드까지 보여야 합니다.
- **제품 워크플로 완성도:** 운영자는 archive, delete, restore, recurrence, export, 명확한
  대시보드 경로를 가져야 합니다.

## 이번 반영 항목

- 백엔드, 에이전트, 프런트엔드를 위한 GitHub Actions 테스트 워크플로를 추가했습니다.
- 루트에 Apache-2.0 `LICENSE`를 추가했습니다.
- eval fixture를 현재 RCA taxonomy에 맞게 갱신하고, image-pull 케이스의 혼동되는
  `OOMKilled` 토큰을 제거했습니다.
- 429, 5xx, 네트워크 상태 실패에 대해 제한된 LLM retry를 추가했습니다.
- `runai-mcp`를 커밋 `527b14087c35edf3467f5028fcc3793475976855`로 고정했습니다.
- LLM usage를 에이전트 호출에서 백엔드 analysis-run metadata와 인시던트 diagnostics 패널까지
  전달하도록 계측했습니다.
- 인시던트 archive, unarchive, soft delete, restore, permanent delete, 30일 trash 보존 및
  purge를 추가했습니다.
- active, archived, trash 뷰와 행 액션, SSE 갱신을 추가했습니다.
- 대시보드 전역 재발 통계와 인시던트별 최근 유사 발생 카운트를 추가했습니다.
- 인시던트 RCA 상세, evidence, alert, 유사 인시던트를 Word로 export하는 기능을 추가했습니다.
- 챗봇 런처가 가리지 않도록 페이지네이션 컨트롤을 가운데로 옮겼습니다.
- 단계별 LLM 모델 라우팅, usage 누락 계측, 추정 LLM 비용과 사용량 관측,
  `/api/v1/stats/llm-spend`를 추가했습니다.
- 최초 완료 기준선을 사용하는 MTTR/time-to-RCA KPI 통계와 프런트엔드 위젯을 추가했습니다.
- gated fixture를 23개로 확장하고 holdout 세트와 실데이터 fixture export 도구를 추가했으며,
  KG on/off A/B 결과를 계속 볼 수 있게 했습니다.
- 수집기 등록과 root-cause family 카탈로그를 외부화하되, 보안상 중요한 도구 경계는 코드에
  유지했습니다.
- 백엔드/에이전트/프런트엔드 live analysis progress를 추가했습니다. 여기에는
  `analysis.progress` SSE, 에이전트 hypothesis ledger 업데이트, workspace thought-process
  timeline이 포함됩니다.
- 프런트엔드 app root를 hooks, dashboard 컴포넌트, workspace 컴포넌트, common control,
  shared utility로 분할했습니다.
- 이 제품은 클러스터별 설치 모델이므로 멀티테넌시는 현재 로드맵에서 제외했습니다.
  cross-tenant 데이터 경계는 운영상 명확한 이점보다 복잡도가 큽니다.
- privileged system agent와 TypeDB 기본값은 보안상 민감한 선택으로 문서화한 채 유지했습니다.
  현재 PoC/default chart에는 허용 가능하지만, 프로덕션 설치에서는 RBAC, 자격 증명,
  네트워크 노출을 검토해야 합니다.

## Eval 결과

확장된 fixture gate 결과:

| 실행 | 결과 |
| --- | --- |
| `python -m eval.run_eval --min-top1 0.8` | KG on, n=23, Top-1 22/23 (96%), Top-3 22/23 (96%), false assertions 0. device-plugin만 있는 모호한 사례는 node pressure로 오판하지 않고 보류합니다. |
| `python -m eval.run_eval --kg-off --min-top1 0.8` | KG off A/B gate. family rule 또는 TypeDB weighting 변경 시 KG-on 결과와 함께 기록합니다 |

gated 세트는 이제 회귀를 차단합니다. holdout 세트는 의도적으로 report-only로 두어,
모든 탐색 케이스를 릴리스 차단 조건으로 만들지 않으면서 약점을 드러낼 수 있게 합니다.

## 남은 로드맵

- TypeDB weighting을 더 강한 기본 의존성으로 만들기 전 더 큰 실제 클러스터 A3 측정과
  KG-on/KG-off 비교.
- Kubernetes scheduling과 GPU/runtime failure가 섞인 noisy multi-signal 인시던트에 대한
  더 어려운 holdout coverage.
- privileged `systemAgent`, TypeDB 자격 증명, 네트워크 정책에 대한 프로덕션 hardening 가이드.
- 인시던트 삭제 또는 영구 purge 시 Slack 스레드 정리.
