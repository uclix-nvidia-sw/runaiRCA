# 배포 가이드

> **관점:** 어떻게 사용하는가 — 게시된 이미지에서 실행 중인 배포까지 진행합니다.
> **이 문서에서 다루는 것:** 컨테이너/Helm 게시 · 설치 경로 · Alertmanager 웹훅 라우팅 · Postgres 및 pgvector 설정 · 읽기 전용 RBAC.

## 컨테이너 및 Helm 배포

리포지토리에는 세 개의 런타임 이미지를 빌드하고 GitHub Container Registry(GHCR)에
게시하는 GitHub Actions 워크플로가 포함되어 있어, 운영자가 배포할 때마다 이미지를 로컬에서
빌드할 필요가 없습니다:

- `ghcr.io/<owner>/runai-rca-backend`
- `ghcr.io/<owner>/runai-rca-agent`
- `ghcr.io/<owner>/runai-rca-frontend`

이 워크플로는 `main` 푸시, `v0.1.0`과 같은 버전 태그, 풀 리퀘스트, 수동 디스패치에서
실행됩니다. 풀 리퀘스트는 이미지를 푸시하지 않고 빌드만 합니다. `main` 푸시는 `main` 및
`sha-...` 태그와 차트 `appVersion`(예: `0.1.0`)을 게시하며, 버전 태그는 `0.1.0`과 같은
semver 태그를 게시합니다.

게시된 GHCR 이미지를 Helm으로 배포하려면 전역 레지스트리를 GitHub 소유자 또는 조직
네임스페이스로 지정하고 공유 태그를 선택합니다:

```bash
helm upgrade --install runai-rca charts/runai-rca \
  --set global.imageRegistry=ghcr.io/<owner> \
  --set backend.image.tag=0.1.0 \
  --set agent.image.tag=0.1.0 \
  --set frontend.image.tag=0.1.0
```

`v0.1.0`과 같은 릴리스 태그의 경우 `--set backend.image.tag=0.1.0`을 사용하고 `agent`와
`frontend`에도 같은 태그를 사용합니다. 컴포넌트 이미지 태그를 비워 두면 차트는 이를
`charts/runai-rca/Chart.yaml`의 `appVersion`으로 기본 설정합니다.

Helm 차트 자체도 `main` 푸시와 버전 태그에서 OCI 아티팩트로 패키징되어 GHCR에 게시됩니다.
리포지토리를 클론하는 대신 차트를 직접 pull하세요:

```bash
helm upgrade --install runai-rca oci://ghcr.io/<owner>/charts/runai-rca \
  --version 0.1.1 \
  --set global.imageRegistry=ghcr.io/<owner>
```

개발용으로는 로컬 이미지 빌드도 여전히 사용할 수 있습니다.

각 런타임은 자체 이미지를 가집니다:

```bash
docker build -t runai-rca-agent:0.1.0 agent
docker build -t runai-rca-backend:0.1.0 backend
docker build -t runai-rca-frontend:0.1.0 frontend
```

Helm 차트는 프런트엔드, 백엔드, 에이전트 서비스, 증거 수집을 위한 읽기 전용 Kubernetes
RBAC, 그리고 Run:ai, Prometheus, Loki, Postgres에 대한
시크릿/구성 경계를 배포합니다.

```bash
helm template runai-rca charts/runai-rca
helm install runai-rca charts/runai-rca \
  --set agent.env.runaiBaseUrl=https://runai.example.com \
  --set agent.env.prometheusUrl=http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090 \
  --set agent.env.lokiUrl=http://loki-read.monitoring.svc.cluster.local:3100 \
  --set-string agent.env.runaiLogNamespaces='runai\,runai-backend' \
  --set secrets.existingSecret=runai-rca-secrets
```

## Alertmanager 웹훅 라우팅

백엔드는 Alertmanager가 `POST /webhook/alertmanager`를 보낼 때만 인시던트를 생성하고
자동 RCA를 시작합니다. 동일한 알림이 Slack에는 도달하지만 Run:AI RCA에는 나타나지 않는다면,
보통 Alertmanager가 Slack 리시버로는 라우팅하지만 RCA 웹훅 리시버로는 라우팅하지 않는
경우입니다.

클러스터 내부에서 백엔드 서비스를 직접 사용하세요:

```text
http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/webhook/alertmanager
```

Alertmanager가 프런트엔드 ingress를 통해 호출해야 한다면, 번들 nginx 구성도 `/webhook/`을
백엔드로 프록시합니다:

```text
https://<frontend-host>/webhook/alertmanager
```

간단한 결합 리시버는 라우팅된 동일한 알림을 Slack과 RCA 양쪽으로 보냅니다:

```yaml
route:
  receiver: slack-and-rca

receivers:
  - name: slack-and-rca
    slack_configs:
      - api_url: <slack-webhook-url>
        channel: <channel>
    webhook_configs:
      - url: http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/webhook/alertmanager
        send_resolved: true
```

리시버를 분리해서 유지할 때는 Slack 라우트가 RCA 이전에 매칭을 멈추지 않도록 하세요.
한 가지 흔한 패턴은 Slack 라우트에 `continue: true`를 두는 것입니다:

```yaml
route:
  routes:
    - matchers:
        - alertname=~".*"
      receiver: slack
      continue: true
    - matchers:
        - alertname=~".*"
      receiver: runai-rca

receivers:
  - name: runai-rca
    webhook_configs:
      - url: http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/webhook/alertmanager
        send_resolved: true
```

라우트를 변경한 후에는 Alertmanager 파드에서의 네트워크 도달성과 백엔드 인테이크를 모두
검증하세요:

```bash
kubectl exec -n <alertmanager-namespace> <alertmanager-pod> -- \
  wget -S -O- http://<release-name>-runai-rca-backend.<namespace>.svc.cluster.local:8080/healthz

curl -s http://<frontend-or-backend-url>/api/v1/alerts
curl -s http://<frontend-or-backend-url>/api/v1/analysis-runs
```

차트를 설치하기 전에 `secrets.existingSecret`이 참조하는 Kubernetes Secret을 생성하세요.
Helm 릴리스와 동일한 네임스페이스를 사용하고, `.env`는 로컬 개발용으로만 유지하며, 배포에서
사용하지 않는 키는 생략하세요:

```bash
kubectl create namespace runai-rca
kubectl create secret generic runai-rca-secrets \
  --namespace runai-rca \
  --from-literal=RUNAI_CLIENT_ID='<runai-client-id>' \
  --from-literal=RUNAI_CLIENT_SECRET='<runai-client-secret>' \
  --from-literal=RUNAI_BEARER_TOKEN='<optional-runai-token>' \
  --from-literal=NVIDIA_API_KEY='<nim-api-key>' \
  --from-literal=LLM_API_KEY='<llm-api-key>' \
  --from-literal=DATABASE_URL='postgres://user:password@postgres.example.com:5432/runai_rca?sslmode=require' \
  --from-literal=POSTGRES_DSN='postgres://user:password@postgres.example.com:5432/runai_rca?sslmode=require' \
  --from-literal=RUNAI_DB_DSN='<optional: read-only DSN for the Run:ai control-plane Postgres, enables the postgres drill-down>' \
  --from-literal=SLACK_BOT_TOKEN='<optional: xoxb- bot token, chat:write>' \
  --from-literal=SLACK_CHANNEL_ID='<optional: channel for incident-analysis summaries>' \
  --from-literal=SLACK_APP_TOKEN='<optional: xapp- app token, connections:write, for the Re-analyze button>'
```

`RUNAI_DB_DSN`과 세 개의 `SLACK_*` 키는 선택 사항입니다 — 이들을 생략하면 각각 플랫폼 DB
드릴다운과 Slack 알림이 비활성화됩니다. Slack에서 "Open Incident" 링크를 사용하려면
`backend.env.dashboardUrl`도 설정해야 합니다.

> **실제 토큰 값을 절대 커밋하지 마세요.** 모든 시크릿은 이 Kubernetes Secret(또는
> `secrets.existingSecret`으로 직접 만든 Secret)에만 넣으세요 — `SLACK_APP_TOKEN`(`xapp-`),
> `SLACK_BOT_TOKEN`(`xoxb-`), API 키, DSN 모두. 차트의 `values.yaml`에 있는 `secrets.*`
> 값은 기본이 빈 문자열이며 Git에서는 빈 상태로 유지해야 합니다. 실제 토큰은 클러스터
> Secret에만 두고, 커밋되는 파일에는 절대 넣지 않습니다.

`--namespace runai-rca --create-namespace`로 해당 네임스페이스에 설치하거나, 위 네임스페이스를
릴리스 네임스페이스로 교체하세요. 서로 다른 Secret 키 이름을 사용한다면 `secrets.keys.*`를
이에 맞게 설정하세요.

기존 Postgres의 경우 `secrets.databaseUrl`을 설정하거나 `secrets.existingSecret`을 통해
Secret을 제공하세요. 차트는 기본적으로 `DATABASE_URL`과 `POSTGRES_DSN`을 읽습니다. 기존
Secret이 다른 키 이름을 사용한다면 `secrets.keys.databaseUrl`과 `secrets.keys.postgresDsn`을
설정하세요. 백엔드는 대상 데이터베이스가 없으면 첫 시작 시 자동으로 생성합니다 — 서버의
`postgres` 유지 관리 데이터베이스에 연결하고, 존재하지 않을 때만 단일
`CREATE DATABASE <name>`을 실행하며, 다른 데이터베이스는 절대 건드리지 않습니다. 따라서
연결하는 사용자에게는 `CREATEDB` 권한이 필요합니다(또는 관리자가 데이터베이스를 미리 생성할 수
있습니다). 백엔드 사용자에게는 테이블을 생성/업데이트할 권한도 필요합니다(그리고 pgvector를
활성화하려면 `CREATE EXTENSION`을 실행할 권한도 필요합니다). pgvector는 데이터베이스 서버
전제 조건입니다: 확장 바이너리가 해당 Postgres 서버에 설치되어 있어야 하며, 백엔드가
시작되기 전에 DBA/관리자가 `runai_rca`와 같은 모든 데이터베이스 안에서
`CREATE EXTENSION IF NOT EXISTS vector;`를 실행해야 할 수 있습니다.

번들된 단일 파드 Postgres의 경우 다음과 같이 활성화합니다:

```bash
helm install runai-rca charts/runai-rca \
  --set postgresql.enabled=true \
  --set postgresql.auth.password=change-me
```

번들 Postgres가 활성화된 상태에서 `secrets.existingSecret`을 Run:ai/NVIDIA 자격 증명에
사용한다면, 차트는 별도의 생성된 데이터베이스 Secret을 만들고 백엔드/에이전트 DB 변수를
이를 가리키도록 설정합니다. 대신 전용 기존 DB Secret을 사용하려면
`secrets.databaseExistingSecret`을 설정하세요.
번들 Postgres 사용자 이름, 비밀번호, 데이터베이스 이름은 차트가 `DATABASE_URL` /
`POSTGRES_DSN`을 생성할 때 URL 인코딩됩니다. `secrets.databaseUrl`, `secrets.postgresDsn`,
또는 기존 Secret에 외부에서 제공되는 DSN은 이미 유효한 Postgres URL이어야 합니다. 기본 번들
이미지는 `pgvector/pgvector:pg16`으로, pgvector 확장이 사전 설치되어 제공되므로 번들
데이터베이스는 별도 설정 없이 실제 벡터 검색을 제공합니다. pgvector를 사용할 수 있으면 백엔드는
HNSW 코사인 인덱스가 있는 `embedding vector(384)` 컬럼을 추가하고 `<=>` 코사인 연산자로
Postgres 내부에서 유사 인시던트 검색을 실행합니다. pgvector를 사용할 수 없으면(예: 확장이 없는
외부 Postgres를 가리킬 때) 백엔드는 `pgvector=unavailable, fallback=jsonb`를 로그로 남기고,
`incident_embeddings.vector_json`의 JSONB sparse 벡터에서 인프로세스 코사인 유사도로 유사
인시던트 검색을 계속 제공합니다.

에이전트는 기본적으로 읽기 전용 클러스터 범위 RBAC를 사용하여 대상 파드, Run:ai 컨트롤 플레인
네임스페이스, 노드 컨텍스트를 검사할 수 있습니다. 이를 선택한 네임스페이스로 제한하려면
클러스터 범위 RBAC를 비활성화하고 쿼리 가능해야 하는 네임스페이스를 나열하세요:

```bash
helm upgrade --install runai-rca charts/runai-rca \
  --set agent.rbac.clusterWide=false \
  --set 'agent.rbac.namespaces[0]=runai' \
  --set 'agent.rbac.namespaces[1]=runai-backend' \
  --set 'agent.rbac.namespaces[2]=runai-vision'
```
