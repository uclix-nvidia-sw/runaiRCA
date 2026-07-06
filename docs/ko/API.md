# API Reference

> **관점:** 레퍼런스 — HTTP 표면(surface).
> **이 문서에서 다루는 것:** Backend 엔드포인트 · Agent 엔드포인트 · 웹훅 accept/ignore 시맨틱.

## 엔드포인트

Backend:

- `POST /webhook/alertmanager`
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
- `GET /api/v1/stats/recurrence?days=7`
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

인시던트 응답은 Alertmanager 상태를 `status` / `resolved_at`으로, 운영자 최종 승인을
`user_approved_at`으로 노출합니다. `AnalysisRun` 응답은 선택 사항인 `metadata`를 포함합니다.
에이전트가 usage 데이터를 반환하면 LLM 토큰 계측값은 `metadata.llm_usage`에 저장됩니다.
인시던트 상세 응답은 최신 실행의 usage를 `token_usage`로 노출하고, UI의 최근 유사 발생
카운트에 쓰이는 `similar_recent_count`를 포함합니다.

`GET /api/v1/events`는 named SSE 이벤트를 내보냅니다. 인시던트 archive, unarchive,
delete, restore, 수동 permanent delete 변경은 `incident.updated`를 발행하므로 다른 대시보드
세션이 active, archived, trash 뷰를 갱신할 수 있습니다.

Agent:

- `POST /analyze`
- `POST /summarize-incident`
- `POST /chat` 현재 인시던트, 알림, 증거, 피드백, 유사 RCA 메모리에 기반한 컨텍스트 인지형(context-aware) RCA 채팅
- `GET /healthz`
