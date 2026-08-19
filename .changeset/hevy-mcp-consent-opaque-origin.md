---
"hevy-mcp": patch
---

Accept the OAuth consent form submission from a sandboxed browser context.

An MCP client may render the authorization page in a context with an opaque
origin, which serializes as the string `null`. The origin allowlist refused it,
so the consent form answered `403 {"error":"Origin not allowed"}` and the
authorization flow could not be completed from such a client.

Allow the opaque origin for `POST /authorize` only, matching the Cloudflare
Worker. The response carries no CORS headers, so a sandboxed document still
cannot read the redirect that carries the authorization code, and the MCP
endpoint keeps refusing opaque origins. Rejected browser origins are now
logged so a future mismatch is visible in deployment logs.
