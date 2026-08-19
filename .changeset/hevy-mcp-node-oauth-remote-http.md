---
"hevy-mcp": minor
---

Make the Node HTTP transport usable as a remote MCP server for browser-based
clients such as Claude custom connectors.

- Serve the MCP endpoint at `/mcp` again, keeping `/mcp-v1` as an alias.
- Add an OAuth 2.1 authorization server behind `HEVY_MCP_OAUTH=1`: RFC 8414 and
  RFC 9728 discovery, RFC 7591 dynamic client registration, authorization code
  with mandatory S256 PKCE, and rotating refresh tokens. Each user supplies
  their own Hevy API key on the consent page, so the server no longer needs a
  shared `HEVY_API_KEY` in this mode.
- Seal the Hevy API key in each grant against the credential secret, so stored
  grants cannot be used without the matching token. Set
  `HEVY_MCP_OAUTH_STORE_PATH` to keep grants across restarts.
- Bind every MCP session to the identity that created it, so a session id
  cannot be driven by a different grant or key.
- Add a CORS layer with an allowlist matching the Worker's, configurable via
  `HEVY_MCP_ALLOWED_ORIGINS`.
- Resolve the public origin from `HEVY_MCP_PUBLIC_URL` or forwarded proxy
  headers so OAuth metadata is correct behind TLS termination, and pin the
  accepted `Host` header when a public URL is configured.
- Add a `/healthz` liveness endpoint for platform health checks.
