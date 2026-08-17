#!/bin/sh

# Default values
TRANSPORT=${HEVY_MCP_TRANSPORT:-stdio}
HOST=${HEVY_MCP_HOST:-0.0.0.0}
PORT=${HEVY_MCP_PORT:-8080}

# Build arguments
ARGS=""

if [ "$TRANSPORT" != "stdio" ]; then
  ARGS="$ARGS --transport $TRANSPORT"
fi

if [ "$TRANSPORT" = "http" ]; then
  ARGS="$ARGS --host $HOST --port $PORT"
fi

# Execute the standalone server with the constructed arguments
exec node /app/standalone.mjs $ARGS

