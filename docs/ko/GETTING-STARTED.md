# Getting Started

> **관점:** 사용 방법 — 처음부터 몇 분 만에 첫 RCA까지.
> **이 문서에서 다루는 것:** 사전 요구사항 · 로컬 실행 · 첫 분석 트리거 · Kubernetes 배포 · 다음 단계 안내.

Run:AI RCA는 세 개의 서비스로 구성됩니다 — **Backend**(Go: Alertmanager 수집 + API), **Agent**(FastAPI: 증거 수집 + RCA 합성), **Frontend**(React 대시보드). 세 서비스 모두 외부 의존성 없이 로컬에서 실행됩니다. 자격 증명이 없으면 Backend는 인메모리 저장소로 폴백하고, Agent는 기본적으로 NAT 엔진을 실행합니다. LLM 자격 증명이 없으면 각 단계가 결정론적으로 저하되며, 엔진이 실패하면 동일한 파이프라인이 직접 실행됩니다.

## 사전 요구사항

- 로컬 개발을 위한 Go, Python 3, Node.js.
- (선택) 실제 배포를 위한 Kubernetes 클러스터 + Helm 3.
- (선택) 라이브 증거를 위한 Run:ai, Prometheus, Loki, Postgres 엔드포인트 — 각 연동은 부재 시 우아하게 성능을 낮춰(degrade) 동작합니다.

## 1. 로컬 실행

```bash
# Agent — FastAPI on :8000
cd agent && python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" && uvicorn app.main:app --reload --port 8000

# Backend — Go on :8080
cd backend && go run .

# Frontend — Vite dev server on :5173, proxies the backend at :8080
cd frontend && npm install && npm run dev
```

대시보드는 http://localhost:5173 에서 엽니다. Frontend는 기본적으로 Backend가 `http://localhost:8080` 에 있을 것으로 기대합니다.

## 2. 첫 RCA 트리거

Alertmanager가 Backend로 POST하면 자동 RCA가 시작됩니다. 이를 로컬에서 시뮬레이션하려면 Alertmanager 형식의 페이로드를 웹훅으로 전송합니다(실제 Alertmanager는 전체 엔벨로프를 보내며, Backend는 Run:ai 컨텍스트를 위해 `alerts[]`의 labels/annotations를 읽습니다):

```bash
curl -s -X POST http://localhost:8080/webhook/alertmanager \
  -H 'Content-Type: application/json' \
  -d '{
    "alerts": [{
      "status": "firing",
      "labels": {"alertname": "GPUWorkloadPending", "severity": "warning",
                 "cluster": "dev", "project": "vision", "namespace": "runai-vision"},
      "annotations": {"description": "Workload pending in queue gpu-a"}
    }]
  }'
```

웹훅은 `accepted`/`ignored` 카운트와 함께 HTTP 202를 반환합니다(severity가 `info`인 알림은 무시되며 아무것도 생성하지 않습니다). 그런 다음 수집 및 분석 상태를 확인합니다:

```bash
curl -s http://localhost:8080/api/v1/alerts
curl -s http://localhost:8080/api/v1/analysis-runs
```

알림이 대시보드에 나타나 인시던트로 상관(correlate)되고, Agent의 `/analyze` 호출이 완료되면 RCA가 함께 표시됩니다. `ok`, `partial`, `pending`의 의미는 [운영 모델](OPERATING-MODEL.md)을, 전체 엔드포인트 목록은 [API 레퍼런스](API.md)를 참고하십시오.

## 3. Kubernetes 배포

이미지와 Helm 차트는 GHCR에 게시되어 있습니다. 자격 증명 Secret을 생성한 뒤 설치합니다:

```bash
kubectl create namespace runai-rca
kubectl create secret generic runai-rca-secrets -n runai-rca \
  --from-literal=RUNAI_CLIENT_ID='<id>' \
  --from-literal=RUNAI_CLIENT_SECRET='<secret>' \
  --from-literal=DATABASE_URL='postgres://user:pw@pg-host:5432/runai_rca?sslmode=require' \
  --from-literal=POSTGRES_DSN='postgres://user:pw@pg-host:5432/runai_rca?sslmode=require'

helm upgrade --install runai-rca oci://ghcr.io/<owner>/charts/runai-rca -n runai-rca \
  --set global.imageRegistry=ghcr.io/<owner> \
  --set secrets.existingSecret=runai-rca-secrets \
  --set agent.env.runaiBaseUrl=https://runai.example.com \
  --set agent.env.prometheusUrl=http://prometheus.monitoring.svc:9090 \
  --set agent.env.lokiUrl=http://loki-read.monitoring.svc.cluster.local:3100
```

외부 데이터베이스가 없습니까? `--set postgresql.enabled=true`를 추가하면 번들된 단일 파드 Postgres(pgvector 포함)를 사용합니다. 마지막 단계는 Alertmanager를 Backend 웹훅으로 라우팅하는 것입니다 — [배포 › Alertmanager 웹훅 라우팅](DEPLOYMENT.md)을 참고하십시오.

## 다음 단계

- [아키텍처](ARCHITECTURE.md) — 웹훅이 어떻게 RCA가 되는가.
- [구성 레퍼런스](CONFIGURATION.md) — 모든 환경 변수와 Helm 값.
- [배포](DEPLOYMENT.md) — 전체 배포, RBAC, 데이터베이스 설정.
- [데이터 저장소](DATABASE.md) — PostgreSQL 스키마와 TypeDB 온톨로지.
