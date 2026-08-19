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

# The server must not run as root. When the container starts as root — which is
# what makes an attached volume usable, since platforms mount them root-owned —
# hand the OAuth store directory to the unprivileged user and then drop to it.
# A container already started unprivileged just runs the server directly.
if [ "$(id -u)" = "0" ]; then
  if [ -n "${HEVY_MCP_OAUTH_STORE_PATH:-}" ]; then
    STORE_DIR=$(dirname "$HEVY_MCP_OAUTH_STORE_PATH")
    # Best effort: a read-only or otherwise unusable mount must not stop the
    # server from starting. It reports the degraded state itself at startup.
    mkdir -p "$STORE_DIR" 2>/dev/null || true
    chown -R node:node "$STORE_DIR" 2>/dev/null || true
  fi
  exec su-exec node node "$@"
fi

exec node "$@"
