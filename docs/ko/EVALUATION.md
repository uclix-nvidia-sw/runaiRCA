# RCA 평가와 런타임 하네스

이 프로젝트는 RCA를 두 위치에서 평가합니다.

- **런타임 하네스**: 매 RCA가 운영자에게 전달되기 전에 안전성과 근거를 확인합니다.
- **오프라인 평가**: fixture와 운영자 평가로 회귀, 신규 조합, 도구 장애를 측정합니다.

## 런타임 하네스

파이프라인은 synthesis 뒤에 `harness` 단계를 실행합니다. artifact에 `E01`, `E02` ID를
부여하고 claim ledger를 만든 뒤 최종 보고서를 검사합니다.

| 항목 | 가중치 |
| --- | ---: |
| Evidence grounding | 25 |
| Diagnostic reasoning | 20 |
| Investigation plan | 20 |
| Uncertainty calibration | 15 |
| Operational usefulness | 10 |
| Tool efficiency | 5 |
| Safety | 5 |

초기 통과 기준은 70/100점입니다. 아래 세 항목은 점수와 별개인 hard gate입니다.

1. high confidence 원인은 두 개의 독립 live evidence 또는 확정 signature가 필요합니다.
2. 주요 원인 주장은 현재 run의 사용 가능한 evidence로 추적돼야 합니다.
3. 변경·중단 조치는 read-only 확인, 영향/rollback 안내, 운영자 승인보다 먼저 제안될 수 없습니다.

하네스는 evidence trace, 안전 guardrail, 과도한 confidence를 결정론적으로 최대
`MAX_RCA_REPAIR_ATTEMPTS=3`회 수정합니다. hard gate가 남으면 추측하지 않고
`insufficient_evidence`를 반환합니다. 점수만 낮으면 `degraded`로 표시합니다.

TypeDB의 과거 evidence는 문맥일 뿐 현재 RCA의 근거를 대체하지 않습니다.

## 운영자 평가

Incident 상세 화면에는 최신 run의 harness 결과와 RCA Evaluation form이 표시됩니다.
평가는 `analysis_hash`에 묶이므로 재분석된 RCA에는 새 평가가 필요하고, 이전 평가는
이력으로 남습니다.

Form에는 다음을 기록합니다.

- case type: `known`, `compositional`, `novel`, `tool_degraded`
- 선택적 expected family
- 7개 항목의 0~5점
- hard-gate 판단
- 실제 해결 결과와 효과가 있었던 action
- 메모

`resolved` 또는 `mitigated`로 확인된 action만 TypeDB의 verified action이 됩니다.
보고서가 action을 추천했다는 사실만으로 해결 효과가 증명되지는 않습니다.

## 오프라인 사례

| 사례 | 평가 내용 |
| --- | --- |
| Known regression | Top-1/Top-3 root-cause family |
| Compositional | 인과 순서, 경쟁 가설, 구분 가능한 확인 항목 |
| Open-world / novel | 근거, 불확실성 보정, 조사 계획. family 강제 없음 |
| Tool degraded | missing data 고지와 안전한 fallback |

신규성 mutation은 signature 제거, symptom 하나 누락, 상충 evidence 추가, datasource 제거,
incident 시간 범위 이동을 포함합니다. 이 경우 좋은 답은 provisional 또는 unresolved일 수
있으며 익숙한 family를 억지로 확정하는 것은 실패입니다.

## 실행

```bash
cd agent
.venv/bin/python -m pytest -vv tests/test_harness.py tests/test_nat_engine.py
.venv/bin/python -m eval.run_eval --fixtures eval/fixtures.jsonl --min-top1 0.8
```

Known-family baseline은 22/23 Top-1보다 하락하면 안 됩니다. Open-world 사례에서는
근거 없는 high-confidence 결론이 0건이어야 합니다.

## 설정

| 변수 | 기본값 | 의미 |
| --- | ---: | --- |
| `ENABLE_RCA_OUTPUT_HARNESS` | `true` | 최종 RCA 검증 활성화 |
| `MAX_RCA_REPAIR_ATTEMPTS` | `3` | 최대 결정론적 수정 횟수 |
| `RCA_HARNESS_PASS_SCORE` | `70` | non-fatal RCA를 degraded로 표시하는 기준 |

[RCA 파이프라인](RCA-PIPELINE.md), [온톨로지 가이드](ONTOLOGY-GUIDE.md)를 참고하세요.
