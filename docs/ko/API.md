# API Reference

> **관점:** 레퍼런스 — HTTP 표면(surface).
> **이 문서에서 다루는 것:** Backend 엔드포인트 · Agent 엔드포인트 · 웹훅 accept/ignore 시맨틱.

## OpenAPI 계약

Backend는 GitBook 호환 **OpenAPI 3.0.3** 계약을
`GET /api/v1/openapi.json`으로 제공합니다. API 포털, 생성형 client, Scalar 또는 Swagger UI
같은 interactive renderer의 기준으로 사용하세요. 현재 계약은 Backend route map을 제공하며,
Knowledge operation은 요청 schema와 lifecycle 응답 코드를 상세히 정의합니다.

배포된 RCA URL의 `/api-docs`를 열면 내장 Scalar 레퍼런스를 볼 수 있습니다. 같은 origin의
계약을 읽고 **Try it**으로 요청을 직접 보냅니다. Scalar 계정이나 hosted Scalar 서비스는
사용하지 않습니다.

## 엔드포인트

Backend:

- `POST /webhook/alertmanager`
- `GET /api/v1/openapi.json`
- `GET /api/v1/incidents?view=active|archived|trash`
- `GET /api/v1/incidents/{id}`
- `POST /api/v1/incidents/{id}/analyze`
- `POST /api/v1/incidents/{id}/resolve`
- `POST /api/v1/incidents/{id}/archive`
- `POST /api/v1/incidents/{id}/unarchive`
- `POST /api/v1/incidents/{id}/restore`
- `DELETE /api/v1/incidents/{id}`
- `DELETE /api/v1/incidents/{id}?permanent=true`
- `GET /api/v1/incidents/{id}/feedback`
- `POST /api/v1/incidents/{id}/feedback`
- `POST /api/v1/incidents/{id}/vote`
- `POST /api/v1/incidents/{id}/comments`
- `PUT /api/v1/incidents/{id}/comments/{comment_id}`
- `DELETE /api/v1/incidents/{id}/comments/{comment_id}`
- `GET /api/v1/alerts`
- `GET /api/v1/alerts/{id}`
- `GET /api/v1/alerts/{id}/feedback`
- `POST /api/v1/alerts/{id}/feedback`
- `POST /api/v1/alerts/{id}/vote`
- `POST /api/v1/alerts/{id}/comments`
- `PUT /api/v1/alerts/{id}/comments/{comment_id}`
- `DELETE /api/v1/alerts/{id}/comments/{comment_id}`
- `POST /api/v1/embeddings/search`
- `GET /api/v1/analysis-runs`
- `GET /api/v1/analysis-runs/{id}/evaluation?author=...`
- `PUT /api/v1/analysis-runs/{id}/evaluation?author=...`
- `GET /api/v1/knowledge-candidates?status=...`
- `GET /api/v1/knowledge-candidates/{id}`
- `POST /api/v1/knowledge-candidates/{id}/decision`
- `GET /api/v1/knowledge-packages?include_retired=true|false`
- `GET /api/v1/knowledge-packages/{id}`
- `POST /api/v1/knowledge-packages/{id}/retire`
- `GET /api/v1/knowledge/runtime-snapshot`
- `GET /api/v1/knowledge/probe-metrics`
- `POST /api/v1/analysis-runs/{id}/progress`
- `GET /api/v1/stats/recurrence?days=7`
- `GET /api/v1/stats/llm-spend?days=7`
- `GET /api/v1/stats/kpi?days=7`
- `GET /api/v1/events`
- `POST /api/v1/chat`

`POST /webhook/alertmanager`는 `status`, `alerts`, `accepted`, `ignored` 카운트와 함께 HTTP 202를 반환합니다. severity가 `info` 또는 `information`인 알림은 ignored로 집계되며, 인시던트, 알림, SSE 이벤트, 분석 실행(analysis run)을 생성하지 않습니다.

`GET /api/v1/incidents`는 기본적으로 active 인시던트 뷰를 반환합니다. 보관된
인시던트는 `view=archived`, 휴지통 보존 기간 안의 soft delete 인시던트는
`view=trash`를 사용합니다. 유효하지 않은 view 값은 HTTP 400을 반환합니다. 목록
페이지네이션의 `total`은 선택한 view 기준으로 계산됩니다.

인시던트 라이프사이클 액션:

- `POST /api/v1/incidents/{id}/resolve`는 RCA에 대한 운영자의 최종 승인을 토글합니다.
  `user_approved_at`을 설정하거나 비우며, `status`와 `resolved_at`은 변경하지 않습니다.
  이 둘은 Alertmanager 기준 인시던트 상태로 유지됩니다. 유사 인시던트 메모리는 이 승인 이후에만
  적재됩니다.
- `POST /api/v1/incidents/{id}/archive`는 데이터를 삭제하지 않고 active 목록에서
  인시던트를 숨깁니다. 같은 조건의 새 알림이 들어오면 자동으로 unarchive됩니다.
- `POST /api/v1/incidents/{id}/unarchive`는 보관된 인시던트를 active 뷰로 되돌립니다.
- `DELETE /api/v1/incidents/{id}`는 인시던트를 휴지통으로 soft delete하고 active 매칭
  인덱스에서 제거합니다. backfill, 대시보드, 채팅 폴백, 메모리 검색은 삭제된
  인시던트를 사용하지 않습니다.
- `POST /api/v1/incidents/{id}/restore`는 매칭 인덱스를 더 새 인시던트가 선점하지 않은
  경우 soft delete 인시던트를 복구합니다.
- `DELETE /api/v1/incidents/{id}?permanent=true`는 인시던트와 연결된 알림, 임베딩,
  피드백, 코멘트, 분석 실행을 영구 삭제합니다.

## Knowledge candidate 결정

모든 knowledge lifecycle 액션은 같은 엔드포인트를 사용합니다. `{candidate_id}`에는
candidate 목록 또는 상세 API가 반환한 값을 넣으세요. `actor`와 `note`는 선택적인 감사
필드입니다.

```http
POST /api/v1/knowledge-candidates/{candidate_id}/decision
Content-Type: application/json
```

```json
{
  "action": "shadow",
  "actor": "on-call@example.com",
  "note": "이 probe template은 활성화 전에 관찰합니다."
}
```

| `action` | 가능한 상태 | 결과 |
| --- | --- | --- |
| `shadow` | candidate가 pending | 검증 후 관찰용 non-active package를 만듭니다. |
| `activate` | candidate가 shadow | 해당 package를 runtime snapshot에 활성화합니다. |
| `approve` | candidate가 pending | 검증 후 즉시 active package를 만듭니다. |
| `reject` | candidate가 pending 또는 shadow | candidate를 거절하며, shadow package는 retired 처리합니다. |

모든 액션의 요청 본문은 같고 `action`만 바뀝니다. `approve`와 `shadow`는 상태 전환 전에
Agent validator를 호출합니다. 성공한 `shadow`, `activate`, `approve` 응답에는 `candidate`와
`package`가 함께 있고, pending candidate의 성공한 `reject` 응답에는 `candidate`가 있습니다.
잘못된 action은 400, validator 거절은 422, 허용되지 않는 lifecycle 전환은 409를 반환합니다.

package를 명시적으로 retire할 때는 `action` 없이 같은 선택 감사 필드를 보냅니다.

```http
POST /api/v1/knowledge-packages/{package_id}/retire
Content-Type: application/json
```

```json
{
  "actor": "on-call@example.com",
  "note": "더 새로운 package로 대체되었습니다."
}
```

`GET /api/v1/stats/recurrence?days=N`은 최근 `N`일 재발 통계를 반환합니다. `days`는
기본값 7이며 1..90 범위로 클램프됩니다.

```json
{
  "data": {
    "days": 7,
    "rate": 0.5,
    "total": 4,
    "recurred": 2,
    "daily": [{"date": "2026-07-06", "total": 1, "recurred": 1, "rate": 1}]
  }
}
```

`GET /api/v1/stats/llm-spend?days=N`은 analysis-run `metadata.llm_usage`를
토큰, 호출 수, 실패 호출 수, 추정 USD 비용, 일별 버킷, 모델별 breakdown으로 집계합니다.
조회 기간은 1..90일 범위입니다.

`GET /api/v1/stats/kpi?days=N`은 time-to-RCA와 time-to-resolve의 평균/p50/p90,
일별 버킷을 반환합니다. time-to-RCA는 인시던트별 최초 성공 완료 시각을 사용하므로 이후
재분석이 기준선을 덮어쓰지 않습니다.

`POST /api/v1/analysis-runs/{id}/progress`는 실행 상태가 `analyzing`인 동안 에이전트의
진행 이벤트를 받습니다. 백엔드는 항목을 `metadata.progress_log`에 최대 200개까지 append하고,
수락한 각 항목을 SSE `analysis.progress`로 broadcast합니다. 완료/실패 실행도 누적된
progress log를 보존합니다.

인시던트 응답은 Alertmanager 상태를 `status` / `resolved_at`으로, 운영자 최종 승인을
`user_approved_at`으로 노출합니다. `AnalysisRun` 응답은 선택 사항인 `metadata`를 포함합니다.
에이전트가 usage 데이터를 반환하면 LLM 토큰 계측값은 `metadata.llm_usage`에 저장됩니다.
인시던트 상세 응답은 최신 실행의 usage를 `token_usage`로 노출하고, UI의 최근 유사 발생
카운트에 쓰이는 `similar_recent_count`를 포함합니다.

인시던트 상세에는 최신 RCA의 `analysis_run_id`, `analysis_hash`, 선택적 `harness`, 선택적
`ontology_reasoning`도 포함됩니다. evaluation GET은 현재 hash와 일치하는 평가만 반환하고,
PUT은 현재 browser actor의 평가를 upsert합니다. 재분석된 RCA에 과거 평가가 붙지 않도록
stale hash는 HTTP 400으로 거절합니다.

`GET /api/v1/events`는 named SSE 이벤트를 내보냅니다. 인시던트 archive, unarchive,
delete, restore, 수동 permanent delete 변경은 `incident.updated`를 발행하므로 다른 대시보드
세션이 active, archived, trash 뷰를 갱신할 수 있습니다. 분석 라이프사이클 이벤트에는
`analysis.started`, `analysis.progress`, `analysis.completed`가 포함됩니다. progress 이벤트는
`run_id`, `phase`, 선택 사항인 collector/hypothesis 필드, confidence 스냅샷, timestamp를
포함합니다.

Agent:

- `POST /analyze`
- `POST /summarize-incident`
- `POST /chat` 현재 인시던트, 알림, 증거, 피드백, 유사 RCA 메모리에 기반한 컨텍스트 인지형(context-aware) RCA 채팅
- `GET /healthz`
