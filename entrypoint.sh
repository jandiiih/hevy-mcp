#!/bin/sh
set -eu

# Transport selection. stdio stays the default so `docker run -i` keeps working
# as an MCP stdio server; hosted platforms set HEVY_MCP_TRANSPORT=http.
TRANSPORT=${HEVY_MCP_TRANSPORT:-stdio}
HOST=${HEVY_MCP_HOST:-0.0.0.0}

# Hosted platforms (Railway, Render, Fly, Heroku) inject the port to listen on
# as PORT. Prefer it so no per-platform configuration is needed, and fall back
# to the project-specific variable and then a fixed default.
PORT=${HEVY_MCP_PORT:-${PORT:-8080}}

set -- /app/standalone.mjs

if [ "$TRANSPORT" != "stdio" ]; then
  set -- "$@" --transport "$TRANSPORT"
fi

if [ "$TRANSPORT" = "http" ]; then
  set -- "$@" --host "$HOST" --port "$PORT"
fi

exec node "$@"
