FROM node:22-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @modelcontextprotocol/server-postgres@0.6.2 \
  && python3 -m venv /opt/mcp-proxy \
  && /opt/mcp-proxy/bin/pip install --no-cache-dir "mcp-proxy==0.12.0" "mcp>=1.17,<2.0" \
  && /opt/mcp-proxy/bin/python -c "from mcp.server.lowlevel.server import request_ctx; from mcp_proxy.proxy_server import create_proxy_server"

ENV PATH="/opt/mcp-proxy/bin:${PATH}" \
    PORT=9904

USER node

CMD ["sh", "-c", "exec mcp-proxy --host 0.0.0.0 --port ${PORT:-9904} -- mcp-server-postgres \"${RUNAI_DB_DSN:-$POSTGRES_DSN}\""]
