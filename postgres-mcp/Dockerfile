FROM node:22-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @modelcontextprotocol/server-postgres@0.6.2 \
  && python3 -m venv /opt/mcp-proxy \
  && /opt/mcp-proxy/bin/pip install --no-cache-dir "mcp-proxy>=0.8"

ENV PATH="/opt/mcp-proxy/bin:${PATH}" \
    PORT=9904

USER node

CMD ["sh", "-c", "exec mcp-proxy --host 0.0.0.0 --port ${PORT:-9904} -- mcp-server-postgres \"${RUNAI_DB_DSN:-$POSTGRES_DSN}\""]
