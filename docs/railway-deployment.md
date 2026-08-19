# Deploying hevy-mcp to Railway

This guide deploys the Node HTTP adapter as a remote MCP server on
[Railway](https://railway.com) and connects it to Claude as a custom connector.
It is an alternative to the hosted Cloudflare Worker for people who prefer to
run their own instance on a container platform.

The result is a public HTTPS endpoint that speaks Streamable HTTP at `/mcp` and
guards it with OAuth 2.1, so Claude can authorize itself in the browser.

## What Railway runs

The repository ships everything Railway needs:

- `Dockerfile` builds the standalone Node bundle (`packages/node/dist/standalone.mjs`).
- `entrypoint.sh` turns environment variables into CLI flags and listens on the
  platform's `PORT`.
- `railway.json` selects the Dockerfile builder, sets the health check to
  `/healthz`, and pins the service to a single replica.

The single replica matters: OAuth grants are held per process, so a second
replica would not recognize tokens issued by the first.

## 1. Create the service

From the repository root, with the [Railway CLI](https://docs.railway.com/guides/cli)
linked to your account:

```bash
railway init
railway up
```

Or create a service in the Railway dashboard from your GitHub fork and let it
deploy on push. Either way Railway detects `railway.json` and builds the
Dockerfile.

## 2. Give the service a domain

Generate a public domain for the service (dashboard: **Settings → Networking →
Generate Domain**, or `railway domain`). Note the resulting hostname, for
example `hevy-mcp-production.up.railway.app`.

## 3. Set the environment variables

| Variable                    | Value                        | Required             |
| --------------------------- | ---------------------------- | -------------------- |
| `HEVY_MCP_TRANSPORT`        | `http`                       | Yes                  |
| `HEVY_MCP_OAUTH`            | `1`                          | Yes, for Claude      |
| `HEVY_MCP_PUBLIC_URL`       | `https://<your-domain>`      | Yes                  |
| `HEVY_MCP_HOST`             | `0.0.0.0`                    | No (already default) |
| `PORT`                      | Injected by Railway          | No                   |
| `HEVY_MCP_OAUTH_STORE_PATH` | `/data/oauth-store.json`     | Recommended          |
| `HEVY_API_KEY`              | Leave unset when OAuth is on | No                   |

`HEVY_MCP_PUBLIC_URL` must match the domain exactly. It is what the server
advertises in its OAuth metadata, and it pins the `Host` header the server will
accept.

```bash
railway variables \
  --set HEVY_MCP_TRANSPORT=http \
  --set HEVY_MCP_OAUTH=1 \
  --set HEVY_MCP_PUBLIC_URL=https://hevy-mcp-production.up.railway.app \
  --set HEVY_MCP_OAUTH_STORE_PATH=/data/oauth-store.json
```

## 4. Add a volume so grants survive a redeploy

Without persistence, every redeploy or restart invalidates outstanding OAuth
grants and you have to reconnect the connector in Claude. Attach a Railway
volume mounted at `/data` (dashboard: **Settings → Volumes**), which is where
`HEVY_MCP_OAUTH_STORE_PATH` above points.

The stored file holds sealed grants: each Hevy API key is encrypted against the
secret inside the client's own token, so the file alone cannot be used to reach
anyone's Hevy account.

## 5. Verify the deployment

```bash
curl https://<your-domain>/healthz
# {"status":"ok"}

curl https://<your-domain>/.well-known/oauth-protected-resource/mcp
# {"resource":"https://<your-domain>/mcp", ...}
```

An unauthenticated MCP request should answer `401` with a `WWW-Authenticate`
header pointing at that metadata document — that is the signal Claude uses to
start the authorization flow:

```bash
curl -i -X POST https://<your-domain>/mcp \
  -H 'Content-Type: application/json' -d '{}'
```

## 6. Add it to Claude

In Claude, go to **Settings → Connectors → Add custom connector** and enter:

```
https://<your-domain>/mcp
```

Claude discovers the authorization server, registers itself, and opens the
consent page. Paste your Hevy API key from
[hevy.com/settings → Developer](https://hevy.com/settings?developer) (requires
Hevy Pro). The key is validated with Hevy before the grant is issued.

After approving, the connector's tools appear in Claude.

## Connecting other clients

Clients that can send a fixed header do not need the OAuth flow. Point them at
the same endpoint with the Hevy API key as the bearer value:

```bash
codex mcp add hevy \
  --url https://<your-domain>/mcp \
  --bearer-token-env-var HEVY_API_KEY
```

## Security notes

- Treat the deployment as a personal instance. Anyone who completes the OAuth
  flow uses their own Hevy key, but the consent page is publicly reachable.
- `HEVY_MCP_ALLOWED_ORIGINS` narrows which browser origins may call the server.
  The default already covers Claude and ChatGPT; set it if you want to restrict
  further.
- Do not set `HEVY_MCP_DISABLE_ORIGIN_CHECK` on a public deployment. It exists
  for local development only.
- Never put the Hevy API key in `HEVY_MCP_HTTP_BEARER_TOKEN`; that variable is a
  separate transport-level gate used only when OAuth is off.

## Troubleshooting

| Symptom                                         | Cause                                                                          |
| ----------------------------------------------- | ------------------------------------------------------------------------------ |
| Claude reports it cannot reach the server       | The domain has no deployment, or `HEVY_MCP_TRANSPORT` is not `http`.           |
| Every request returns `403 Invalid Host header` | `HEVY_MCP_PUBLIC_URL` does not match the domain Claude is calling.             |
| Connector disconnects after each deploy         | No volume is attached, so grants are lost. See step 4.                         |
| `401` even after authorizing                    | The Hevy key behind the grant was rotated. Reconnect the connector.            |
| Health check fails during deploy                | The service is not listening on Railway's `PORT`. Leave `HEVY_MCP_PORT` unset. |
