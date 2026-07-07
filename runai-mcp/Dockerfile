# Image for the Run:ai MCP integration.
#
# runai-mcp (github.com/sejongjeong/runai-mcp) is a stdio-only MCP server, so it
# runs behind mcp-proxy which exposes it over streamable HTTP for the RCA agent
# (RUNAI_MCP_URL=http://<release>-runai-mcp:8809/mcp). Auth (RUNAI_CLIENT_ID/SECRET,
# RUNAI_API_BASE_URL) is injected as env by the chart from the runai-rca secret.
#
# Build:  docker build -t <registry>/runai-mcp:latest ./runai-mcp
# Pin RUNAI_MCP_REF to a commit/tag for reproducible builds.
ARG RUNAI_MCP_REPO=https://github.com/sejongjeong/runai-mcp.git
ARG RUNAI_MCP_REF=527b14087c35edf3467f5028fcc3793475976855

FROM node:20-slim AS build
ARG RUNAI_MCP_REPO
ARG RUNAI_MCP_REF
# Upstream runai-mcp pins typescript@^6 in devDeps while ts-jest requires
# typescript <6, so a strict install fails on ERESOLVE. Relax peer resolution.
ENV npm_config_legacy_peer_deps=true
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
# The server reads the OpenAPI spec at runtime — index.js resolves
# `<dist>/../spec/saas-latest.yaml` and process.exit(1)s if it's missing.
# tsc does NOT emit the YAML into dist, so copy the spec dir explicitly or the
# container CrashLoopBackOffs on startup ("Failed to build registry").
COPY --from=build /app/spec ./spec
# Non-root; the chart also applies its securityContext.
USER 1000
EXPOSE 8809
# Expose stdio runai-mcp over HTTP. mcp-proxy does not reliably pass custom pod
# env to the child process, so inject the env that runai-mcp reads explicitly.
CMD ["sh", "-c", "exec mcp-proxy --host 0.0.0.0 --port 8809 -- env RUNAI_API_BASE_URL=\"$RUNAI_API_BASE_URL\" RUNAI_CLIENT_ID=\"$RUNAI_CLIENT_ID\" RUNAI_CLIENT_SECRET=\"$RUNAI_CLIENT_SECRET\" RUNAI_API_TOKEN=\"$RUNAI_API_TOKEN\" LOG_LEVEL=\"${LOG_LEVEL:-info}\" node /app/dist/index.js"]
