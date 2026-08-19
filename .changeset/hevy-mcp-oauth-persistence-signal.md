---
"hevy-mcp": patch
---

Report at startup whether OAuth grants actually persist.

`HEVY_MCP_OAUTH_STORE_PATH` pointing at a path the process cannot write — the
usual shape of a container volume mounted for a different user — previously
degraded to memory-only silently, and the symptom appeared much later as every
client being disconnected by a redeploy.

The store now probes the path when it is constructed and exposes whether it is
writable, and startup logs state plainly whether clients stay connected across
restarts.
