# RCA 출력 용어집

> **관점:** 운영자에게 표시되는 RCA 출력 읽기.
> **이 문서에서 다루는 것:** 패밀리 레이블 · 근거(support) 상태 · 평가 · 출력 검증 · 보고서 생성.

이 문서는 Run:AI RCA에서 구현상 두 가지 이상 의미를 갖는 용어를 간결하게 정리한 레퍼런스입니다.

## 용어

### `family`

**정의.** `family`는 `agent/knowledge/families.yaml`의 16개 장애 범주 중 하나이며, `agent/app/knowledge.py`의 `DEFAULT_FAMILY_RULES`에도 미러링되어 있습니다. 결정론적 ranker는 family의 `keywords`를 사용해 점수를 계산합니다. `planner_keywords`는 조사 planner가 가설을 회수하는 데만 도움을 주며 family 점수에는 절대 반영되지 않습니다. 어떤 family도 ranking 증거 하한에 도달하지 못하면 파이프라인은 합성 family인 `insufficient_evidence`를 주입합니다.

**어디에서 보이나.** 순위가 매겨진 후보의 근본 원인 family 레이블, RCA 헤드라인, harness claim, 관련 증거 및 지식 레코드에서 보입니다.

### `supported` / `supporting`

**정의.** 이 단어는 기술적으로 서로 다른 네 가지 의미를 가집니다. 서로 관련은 있지만, 서로 다른 단계에서 계산되고 서로 다른 객체에 붙습니다.

1. **Investigator 가설 ledger 상태:** `agent/app/services/investigator.py:49`의 `_LEDGER_STATUSES = {open, testing, supported, refuted, uncertain}` 중 하나입니다. 조사 loop가 해당 가설을 더 조사하지 않아도 될 만큼 뒷받침되었다고 판단한다는 뜻입니다.
2. **Evidence-blackboard fact 상태:** `agent/app/services/evidence_blackboard.py:27`의 `HypothesisStatus = Literal["untested", "testing", "supported", "refuted", "provisional"]` 중 하나입니다. blackboard의 가설/fact에 기록되는 상태입니다.
3. **Harness의 `diagnosis_state`:** `agent/app/services/harness.py:343-344`의 운영자 표시용 판정 상태입니다. family가 존재하고 confidence가 low가 아니면 harness가 `supported`로 설정합니다. 그렇지 않으면 confidence가 low일 때 `provisional`, family가 없거나 `insufficient_evidence`일 때 `unresolved`입니다.
4. **직접 증거:** reasoning trace v3의 `supporting_source_groups`와 보고서의 `supporting_artifacts`는 근본 원인을 직접 뒷받침하는 구체적인 증거 artifact를 가리킵니다. 이는 반박 증거 또는 맥락 증거와 구분됩니다(`agent/app/services/pipeline.py:1297, 3267`).

이 네 의미를 혼동해서는 안 됩니다. Investigator ledger에서 가설이 `supported`라는 것은 harness가 진단을 `supported`로 표시했다는 뜻이 아닙니다.

**어디에서 보이나.** 조사 trace와 가설 ledger, blackboard fact, harness의 `diagnosis_state`, reasoning trace, 보고서의 증거 섹션에서 보입니다. 주변 객체와 field 이름으로 어떤 의미인지 구분합니다.

### `evaluation`

**정의.** `evaluation`에는 두 가지 의미가 있습니다. 첫째, probe evaluation은 `agent/app/services/probe_evaluation.py`가 명시적으로 작성된 probe signal을 바탕으로 계산하는 결정론적 판정 `supports`, `refutes`, `inconclusive`, `unavailable`입니다. 둘째, evaluation은 backend/frontend의 `EvaluationView`를 통해 완료된 run을 사람이 검토하는 절차입니다. 이 검토와 지식 승격 검사가 지식 승격 가능 여부를 결정할 수 있습니다.

**어디에서 보이나.** 첫 번째 의미는 probe assessment와 조사 기록에서, 두 번째 의미는 완료된 run의 Evaluation 화면, review 점수, 지식 승격 preview에서 보입니다.

### `harness`

**정의.** `harness`는 `agent/app/services/harness.py`의 합성 후 출력 검증기입니다. 지원되지 않은 high confidence, 누락된 증거 trace, 잘못된 증거 링크, 해결되지 않은 모순, guardrail 없는 위험한 조치에 대한 hard gate를 검사하고 rubric 점수도 계산합니다. 보고서를 repair하거나 판정을 낮추거나, 최상위 원인을 `insufficient_evidence`로 바꾸어 abstain할 수 있습니다. `ENABLE_RCA_OUTPUT_HARNESS`로 제어하며 기본값은 on입니다.

**어디에서 보이나.** 최종 response context의 harness 상태/점수, `diagnosis_state`, hard-gate 결과, repair 또는 abstain된 RCA 출력에서 보입니다.

### `synthesis`

**정의.** `synthesis`는 운영자에게 표시할 최종 보고서를 생성하는 단계입니다. `agent/app/services/pipeline.py`의 `synthesize_stage`가 결정론적 영어 보고서를 만들며, 한국어로 설정되고 조건이 맞으면 적격 증거에 엄격히 근거한 한국어 LLM 보고서로 덮어쓸 수 있습니다.

**어디에서 보이나.** `synthesize` 파이프라인 단계와 최종 보고서의 summary, detail, 조치, caveat, 증거 표시에서 보입니다.
