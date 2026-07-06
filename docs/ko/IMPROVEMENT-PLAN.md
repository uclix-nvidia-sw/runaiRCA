# 개선 계획

> **관점:** 리뷰 후속 조치 — 이번에 바꾼 것과 남은 것.
> **이 문서에서 다루는 것:** 리뷰 점수 · 반영된 퀵윈과 기능 · 측정된 eval 결과 · 남은 로드맵.

모의 심사에서 Run:AI RCA는 **66.7/100**을 받았습니다. 핵심 문제는 거대한 시스템 하나가
통째로 빠진 것이 아니라, 운영 도구를 매일 믿고 쓰게 만드는 작은 조각들이 부족하다는 점이었습니다.
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

## Eval 결과

fixture taxonomy 갱신 후 결과:

| 실행 | 결과 |
| --- | --- |
| `python -m eval.run_eval` | KG on, n=8, Top-1 8/8 (100%), Top-3 8/8 (100%), false assertions 0 |
| `python -m eval.run_eval --kg-off` | KG off, n=8, Top-1 8/8 (100%), Top-3 8/8 (100%), false assertions 0 |

현재 작은 fixture 세트에서는 A/B가 동률입니다. 더 큰 A3 방식 재측정에서 분명한 이점이
나오기 전까지 TypeDB는 선택 경로로 유지합니다.

## 남은 로드맵

- 작업 유형과 confidence에 따른 모델 차등 적용.
- mean time to RCA, 재발 추세, 자동화 커버리지, 운영자 피드백 품질을 보는 KPI 대시보드.
- Kubernetes, Prometheus, Loki, Run:ai, Postgres, system evidence를 독립적으로 확장하기 위한
  수집기 플러그인화.
- 데이터 접근, 인시던트 뷰, 자격 증명에 대한 멀티테넌시 경계.
- 더 큰 A3 재측정과 KG-on/KG-off A/B 이후 TypeDB 기본값 결정.
- 대시보드 표면이 안정화된 뒤 `App.tsx`를 더 작은 기능 모듈로 분할.
- `systemAgent`를 기본 privileged로 둘지 재검토.
- 인시던트 삭제 또는 영구 purge 시 Slack 스레드 정리.
