# Operations & Troubleshooting

> **관점:** RCA 플랫폼 자체를 운영하는 것 — 정상 작동을 확인하는 방법과 그렇지 않을 때
> 무엇을 점검할지.
> **이 문서에서 다루는 것:** 헬스 체크 · "RCA 리포트 없음" 원인 · TypeDB / pgvector /
> Slack 진단 · 지식 그래프 검사 · 일반적인 실패 시그니처.

이 문서는 **Run:AI RCA** 자체를 운영하는 것에 대한 것이지, 그것이 분석하는 인시던트에
대한 것이 아닙니다. 분석 흐름은 [RCA 파이프라인](RCA-PIPELINE.md)을, 스토어는
[데이터 스토어](DATABASE.md)를 참고하십시오.

## Is it actually working?

자동 RCA는 **Alertmanager가 Backend 웹훅에 POST한 이후**에만 시작됩니다 — Alertmanager의
Slack 알림만으로는 RCA 수신기가 라우팅되었음을 증명하지 못합니다. 실제 경로를 확인하십시오:

```bash
# Alerts and analysis runs the backend has actually received/started
curl -s http://<backend-or-frontend>/api/v1/alerts | jq '.[0]'
curl -s http://<backend-or-frontend>/api/v1/analysis-runs | jq '.[0]'

# Agent process liveness (means the API is up, NOT that a collector produced evidence)
curl -s http://<agent>/healthz
```

- UI의 수집기 카드는 **실행이 수집기 `artifacts`를 저장한 이후에만** `ok`로 바뀝니다 —
  `Running` 파드나 `200` 헬스 체크만으로는 충분하지 않습니다.
- `ENABLE_NAT_RUNTIME=true`는 `/analyze` 합성에 영향을 줍니다. `/chat`은 결정론적 컨텍스트
  답변을 반환하며 LLM 경로를 직접 호출하지 않습니다.

## "No RCA report was produced"

이 목록을 위에서부터 따라가십시오 — 흔한 원인을 가장 흔한 것부터 나열했습니다:

1. **Alertmanager가 웹훅으로 라우팅되지 않았습니다.** 알림이 Slack에는 도달했지만
   `POST /webhook/alertmanager`에는 도달하지 않았습니다. Alertmanager 수신기/라우트를
   확인하십시오([배포](DEPLOYMENT.md) 참고). 그 알림은 `/api/v1/alerts`에 나타나지 않습니다.
2. **알림이 해결되어 건너뛰어졌습니다.** 해결된 알림은 의도적으로 분석하지 않습니다.
   예상된 동작입니다.
3. **팬아웃 / 속도 제한.** 급증으로 인해 `MAX_AUTO_ANALYZE_FANOUT`(웹훅당) 또는
   `MAX_CONCURRENT_AGENT_RUNS`를 초과했습니다. 백필 루프
   (`ANALYSIS_BACKFILL_INTERVAL_SECONDS`)가 누락된 알림을 다시 구동합니다 — 한 사이클을
   기다리거나 제한을 올리십시오.
4. **에이전트가 끝나기 전에 Backend가 연결을 끊었습니다.** `AGENT_REQUEST_TIMEOUT_SECONDS`
   (1560)가 에이전트의 `ANALYSIS_DEADLINE_SECONDS`(1500)보다 낮게 설정되면, 백엔드가 분석
   도중에 취소하고 저하된 리포트가 유실됩니다. 백엔드 > 에이전트를 유지하십시오.
5. **Persist 실패는 의도된 조기 반환입니다.** 백엔드는 실행을 영속화할 수 없으면 조기
   반환합니다. 이것은 설계상 의도된 것이며(테스트도 되어 있음) 버그가 아닙니다. 백엔드 로그와
   Postgres 상태를 확인하십시오.

타임아웃을 지나 `analyzing` 상태에 갇힌 실행은 다음 백엔드 시작 시 `failed`로 정리됩니다
(`ReapStaleAnalyzingRuns`). 영원히 멈춰 있지 않습니다.

## TypeDB (ontology) diagnostics

그래프는 선택 사항입니다 — 꺼져 있거나 도달할 수 없을 때에도 분석은 계속 실행되며, 리포트는
단순히 Knowledge Base 섹션을 생략합니다(그 이유는 `warnings`에 기록됩니다).

```bash
# Did the schema/knowledge load job run?
kubectl get jobs -n <ns> | grep typedb
kubectl logs -n <ns> job/<release>-typedb-load-schema

# Did the ingest cron project incidents?
kubectl get cronjob,jobs -n <ns> | grep ingest
kubectl logs -n <ns> job/$(kubectl get jobs -n <ns> -o name | grep ingest | tail -1 | cut -d/ -f2)
# → "fetched N incident(s); ingesting M ... done: X written"

# Inspect the graph without writing TypeQL
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --recent 20
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --incident INC-...
kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --count
```

- **그래프가 비어 보이나요?** 인제스트는 **해결된 지 `resolvedGraceHours`(6h) 이상 지난**
  인시던트만 프로젝션합니다. 새로 만든 클러스터에는 아직 적격한 대상이 없을 뿐입니다.
  `--recent`가 행을 반환하는데 인시던트 하나가 누락되었다면, 그 인시던트의 `resolved_at`이
  null일 수 있습니다(UI "Resolved" ≠ DB `resolved_at` 설정됨).
- **`warnings`에 "TypeDB knowledge-graph query failed (...)"가 표시되나요?** — 메시지가
  원인을 명시합니다(연결 거부 vs 인증 vs `[TQLxx]` 쿼리 오류). 이것은 결코 조용히
  삼켜지지 않습니다.
- 필요 시 인제스트를 다시 실행하십시오:
  `kubectl create job -n <ns> --from=cronjob/<release>-typedb-ingest manual-ingest-1`.

TypeDB Studio 접근은 [Knowledge Base → Querying the graph](KNOWLEDGE-BASE.md)를
참고하십시오.

## pgvector diagnostics

pgvector는 **백엔드**가 소유합니다. JSONB 희소 벡터 코사인 폴백으로 우아하게 저하되므로,
유사 인시던트 검색은 항상 작동합니다.

- 시작 로그는 `pgvector=enabled` 또는 `pgvector=unavailable, fallback=jsonb`를 보고합니다.
- `unavailable`은 `vector` 확장이 설치되지 않았거나 앱 사용자가 `CREATE EXTENSION vector`를
  할 수 없다는 의미입니다. 번들된 `pgvector/pgvector:pg16` 이미지에는 이것이 포함되어
  있습니다. 외부 Postgres의 경우 DBA가 설치해야 합니다([Backend README](../../backend/README.md)
  참고).
- 유사 인시던트는 `/analyze` 요청 페이로드(`similar_incidents` + `feedback_hints`)를 통해
  에이전트에 공급됩니다 — 에이전트는 pgvector를 직접 쿼리하지 않습니다.

## Slack diagnostics

알림에는 인커밍 웹훅이 아니라 **봇 토큰**(`SLACK_BOT_TOKEN` + `SLACK_CHANNEL_ID`)이
필요합니다(`chat.postMessage`는 스레딩에 필요한 `ts`를 반환합니다).

- **아무것도 게시되지 않나요?** 두 환경 변수가 모두 설정되었는지, 토큰에 `chat:write`
  권한이 있는지, 그리고 **봇이 채널에 초대되었는지** 확인하십시오. 전달은 파이어 앤
  포겟 방식입니다 — 실패는 로그에 기록되며(`slack notify failed for incident ...`) 실행을
  절대 차단하지 않습니다.
- **일부 실행만 게시됩니다.** 설계상 그렇습니다: 인시던트의 **첫 번째** 완료된 분석(루트
  메시지)과 이후의 **운영자 주도** 재분석(`manual`/`comment`/`feedback`/`chat`, 스레드
  답글로)만 게시됩니다. 자동/백필 후속 및 실패한 실행은 의도적으로 조용합니다.
- **Open Incident** 버튼에는 `DASHBOARD_URL` 설정이 필요합니다. **Re-analyze** 버튼에는
  `SLACK_APP_TOKEN`이 필요합니다(앱에서 Socket Mode + Interactivity 활성화).

## Evidence looks thin

수집기 카드가 `unavailable`이거나 리포트에 *"증거를 찾기 어렵습니다"*라고 표시되는 경우:

- 해당 수집기의 데이터 소스가 구성되지 않았거나 도달할 수 없습니다(예: `LOKI_URL`,
  `PROMETHEUS_URL`, `SYSTEM_AGENT_URL` 미설정). 리포트는 원인을 지어내는 대신 누락된
  소스를 명시합니다 — 이것은 정직성 게이트이지 버그가 아닙니다.
- 스텝별 상한은 의도적으로 넉넉합니다(120s). "최적화"를 위해 줄이지 마십시오 — 그러면
  얕은 증거가 다시 도입됩니다. 지연 시간이 중요하다면 대신 `ANALYSIS_DEADLINE_SECONDS`를
  조정하십시오.
- 에이전트가 더 깊이 파고들게 하려면 `ENABLE_INVESTIGATION_LOOP`와
  `ENABLE_AGENT_DRILLDOWN`이 켜져 있고(Helm 기본값 true) LLM이 구성되어 있는지 확인하십시오 —
  LLM이 없으면 이 루프들은 건너뛰어지고 증거는 일회성이 됩니다.

## Where to look

| 증상 | 먼저 확인할 것 |
|---|---|
| 알림이 전혀 없음 | Alertmanager 라우트 → `/api/v1/alerts` |
| 알림은 있으나 실행 없음 | `/api/v1/analysis-runs`, 팬아웃/속도 제한, 에이전트 `/healthz` |
| 실행이 `failed` | 백엔드 로그, 에이전트 데드라인 vs 백엔드 타임아웃 |
| Knowledge Base 섹션이 비어 있음 | TypeDB 도달 가능? 인제스트 실행됨? `warnings` 필드 |
| 유사 인시던트 없음 | pgvector 시작 로그, embeddings 테이블 채워짐 여부 |
| Slack 메시지 없음 | 봇 토큰 + 채널 + 봇 초대됨; 실행 소스 적격 여부 |
| 얕은 증거 | 데이터 소스 URL 설정됨; 드릴다운용 LLM 구성됨 |
