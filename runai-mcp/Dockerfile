# Sidecar image for the Run:ai MCP integration.
#
# runai-mcp (github.com/sejongjeong/runai-mcp) is a stdio-only MCP server, so it
# runs behind mcp-proxy which exposes it over streamable HTTP for the RCA agent
# (RUNAI_MCP_URL=http://localhost:8809/mcp). Auth (RUNAI_CLIENT_ID/SECRET,
# RUNAI_API_BASE_URL) is injected as env by the chart from the runai-rca secret.
#
# Build:  docker build -t <registry>/runai-mcp:latest ./runai-mcp
# Pin RUNAI_MCP_REF to a commit/tag for reproducible builds.
ARG RUNAI_MCP_REPO=https://github.com/sejongjeong/runai-mcp.git
ARG RUNAI_MCP_REF=main

FROM node:20-slim AS build
ARG RUNAI_MCP_REPO
ARG RUNAI_MCP_REF
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN git clone "${RUNAI_MCP_REPO}" . && git checkout "${RUNAI_MCP_REF}" \
    && npm ci --no-audit --no-fund && npm run build && npm prune --omit=dev

FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/mcp-proxy && /opt/mcp-proxy/bin/pip install --no-cache-dir "mcp-proxy>=0.8"
ENV PATH="/opt/mcp-proxy/bin:${PATH}"
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
# Non-root; the chart also applies its securityContext.
USER 1000
EXPOSE 8809
# Expose the stdio runai-mcp server over streamable HTTP at :8809/mcp.
# (mcp-proxy flags vary by version — override the chart command if yours differs.)
CMD ["mcp-proxy", "--host", "0.0.0.0", "--port", "8809", "--", "node", "/app/dist/index.js"]
