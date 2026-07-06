# API Reference

> **관점:** 레퍼런스 — HTTP 표면(surface).
> **이 문서에서 다루는 것:** Backend 엔드포인트 · Agent 엔드포인트 · 웹훅 accept/ignore 시맨틱.

## 엔드포인트

Backend:

- `POST /webhook/alertmanager`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{id}`
- `POST /api/v1/incidents/{id}/analyze`
- `POST /api/v1/incidents/{id}/resolve`
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
- `GET /api/v1/events`
- `POST /api/v1/chat`

`POST /webhook/alertmanager`는 `status`, `alerts`, `accepted`, `ignored` 카운트와 함께 HTTP 202를 반환합니다. severity가 `info` 또는 `information`인 알림은 ignored로 집계되며, 인시던트, 알림, SSE 이벤트, 분석 실행(analysis run)을 생성하지 않습니다.

Agent:

- `POST /analyze`
- `POST /summarize-incident`
- `POST /chat` 현재 인시던트, 알림, 증거, 피드백, 유사 RCA 메모리에 기반한 컨텍스트 인지형(context-aware) RCA 채팅
- `GET /healthz`
