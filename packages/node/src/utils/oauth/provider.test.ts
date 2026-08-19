import { createHash, randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { McpServer } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startStreamableHttpServer } from "../streamable-http.js";
import { HevyOAuthProvider } from "./provider.js";
import { OAuthStore } from "./store.js";

/**
 * Drives the authorization flow a remote MCP client performs: discovery,
 * dynamic registration, consent, PKCE token exchange, an authenticated MCP
 * session, and refresh. The Hevy API is never contacted — the key validator is
 * injected — so this lane stays deterministic and needs no credentials.
 */

const VALID_KEY = "valid-hevy-key";
const OTHER_KEY = "other-hevy-key";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";

const handles: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
	await Promise.all(handles.splice(0).map((handle) => handle.close()));
	vi.restoreAllMocks();
});

interface StartedServer {
	base: string;
	apiKeys: string[];
}

async function startServer(
	options: {
		persistencePath?: string;
		allowDirectApiKeyBearer?: boolean;
		publicOrigin?: string;
	} = {},
): Promise<StartedServer> {
	const store = new OAuthStore({ persistencePath: options.persistencePath });
	const oauth = new HevyOAuthProvider({
		store,
		resourcePath: "/mcp",
		validateApiKey: (candidate) =>
			Promise.resolve(
				candidate === VALID_KEY || candidate === OTHER_KEY
					? "valid"
					: "invalid",
			),
	});
	const apiKeys: string[] = [];
	const handle = await startStreamableHttpServer(
		{ transport: "http", host: "127.0.0.1", port: 0 },
		"",
		({ apiKey }) => {
			apiKeys.push(apiKey);
			const server = new McpServer({ name: "test-server", version: "1.0.0" });
			server.registerTool(
				"whoami",
				{ description: "Echoes the session key" },
				() => Promise.resolve({ content: [{ type: "text", text: apiKey }] }),
			);
			return Promise.resolve(server);
		},
		{},
		{
			oauth,
			allowDirectApiKeyBearer: options.allowDirectApiKeyBearer,
			publicOrigin: options.publicOrigin,
		},
	);
	handles.push(handle);
	const address = handle.server.address() as AddressInfo;
	return { base: `http://127.0.0.1:${address.port}`, apiKeys };
}

async function registerClient(base: string): Promise<string> {
	const response = await fetch(`${base}/register`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			redirect_uris: [REDIRECT_URI],
			client_name: "Claude",
			token_endpoint_auth_method: "none",
		}),
	});
	expect(response.status).toBe(201);
	const body = (await response.json()) as { client_id: string };
	return body.client_id;
}

interface Pkce {
	verifier: string;
	challenge: string;
}

function createPkce(): Pkce {
	const verifier = randomBytes(32).toString("base64url");
	return {
		verifier,
		challenge: createHash("sha256").update(verifier).digest("base64url"),
	};
}

/** Complete the consent form and return the issued authorization code. */
async function authorize(
	base: string,
	clientId: string,
	pkce: Pkce,
	apiKey: string,
): Promise<string> {
	const authorizeUrl =
		`${base}/authorize?response_type=code&client_id=${clientId}` +
		`&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
		`&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=st`;
	const page = await fetch(authorizeUrl);
	expect(page.status).toBe(200);
	const html = await page.text();
	const encoded = /name="oauth_request" value="([^"]+)"/u.exec(html)?.[1];
	expect(encoded).toBeTruthy();

	const submitted = await fetch(`${base}/authorize`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			oauth_request: encoded as string,
			hevy_api_key: apiKey,
		}),
		redirect: "manual",
	});
	expect(submitted.status).toBe(302);
	const location = new URL(submitted.headers.get("location") as string);
	expect(location.searchParams.get("state")).toBe("st");
	return location.searchParams.get("code") as string;
}

interface TokenResponse {
	access_token: string;
	refresh_token: string;
	expires_in: number;
	token_type: string;
}

async function exchangeCode(
	base: string,
	clientId: string,
	code: string,
	verifier: string,
): Promise<Response> {
	return fetch(`${base}/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			code,
			code_verifier: verifier,
			client_id: clientId,
			redirect_uri: REDIRECT_URI,
		}),
	});
}

/** Initialize an MCP session and return its session id. */
async function initializeSession(
	base: string,
	authorization: string,
): Promise<Response> {
	return fetch(`${base}/mcp`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Accept: "application/json, text/event-stream",
			Authorization: authorization,
		},
		body: JSON.stringify({
			jsonrpc: "2.0",
			id: 1,
			method: "initialize",
			params: {
				protocolVersion: "2025-06-18",
				capabilities: {},
				clientInfo: { name: "test-client", version: "1.0.0" },
			},
		}),
	});
}

describe("Node OAuth 2.1 provider", () => {
	it("issues tokens through the full authorization code flow", async () => {
		const { base } = await startServer();
		const clientId = await registerClient(base);
		const pkce = createPkce();
		const code = await authorize(base, clientId, pkce, VALID_KEY);

		const response = await exchangeCode(base, clientId, code, pkce.verifier);
		expect(response.status).toBe(200);
		const tokens = (await response.json()) as TokenResponse;
		expect(tokens.token_type).toBe("Bearer");
		expect(tokens.access_token.split(":")).toHaveLength(3);
		expect(tokens.refresh_token.split(":")).toHaveLength(3);
		expect(tokens.expires_in).toBe(7 * 24 * 60 * 60);
	});

	it("serves an MCP session with the Hevy key from the grant", async () => {
		const { base, apiKeys } = await startServer();
		const clientId = await registerClient(base);
		const pkce = createPkce();
		const code = await authorize(base, clientId, pkce, VALID_KEY);
		const tokens = (await (
			await exchangeCode(base, clientId, code, pkce.verifier)
		).json()) as TokenResponse;

		const session = await initializeSession(
			base,
			`Bearer ${tokens.access_token}`,
		);
		expect(session.status).toBe(200);
		expect(session.headers.get("mcp-session-id")).toBeTruthy();
		// The session was built with the key sealed into the grant, not a
		// server-configured one.
		expect(apiKeys).toEqual([VALID_KEY]);
		await session.body?.cancel();
	});

	it("rejects an MCP request with no access token and points at discovery", async () => {
		const { base } = await startServer();
		const response = await fetch(`${base}/mcp`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: "{}",
		});
		expect(response.status).toBe(401);
		expect(response.headers.get("www-authenticate")).toContain(
			"/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("refuses to reuse an authorization code", async () => {
		const { base } = await startServer();
		const clientId = await registerClient(base);
		const pkce = createPkce();
		const code = await authorize(base, clientId, pkce, VALID_KEY);

		expect(
			(await exchangeCode(base, clientId, code, pkce.verifier)).status,
		).toBe(200);
		const replay = await exchangeCode(base, clientId, code, pkce.verifier);
		expect(replay.status).toBe(400);
		expect((await replay.json()) as { error: string }).toMatchObject({
			error: "invalid_grant",
		});
	});

	it("refuses a token exchange with the wrong PKCE verifier", async () => {
		const { base } = await startServer();
		const clientId = await registerClient(base);
		const pkce = createPkce();
		const code = await authorize(base, clientId, pkce, VALID_KEY);

		const response = await exchangeCode(
			base,
			clientId,
			code,
			createPkce().verifier,
		);
		expect(response.status).toBe(400);
		expect((await response.json()) as { error: string }).toMatchObject({
			error: "invalid_grant",
		});
	});

	it("rotates tokens on refresh and invalidates the used refresh token", async () => {
		const { base } = await startServer();
		const clientId = await registerClient(base);
		const pkce = createPkce();
		const code = await authorize(base, clientId, pkce, VALID_KEY);
		const first = (await (
			await exchangeCode(base, clientId, code, pkce.verifier)
		).json()) as TokenResponse;

		const refreshed = await fetch(`${base}/token`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: first.refresh_token,
				client_id: clientId,
			}),
		});
		expect(refreshed.status).toBe(200);
		const second = (await refreshed.json()) as TokenResponse;
		expect(second.access_token).not.toBe(first.access_token);
		expect(second.refresh_token).not.toBe(first.refresh_token);

		// The rotated-out refresh token must no longer work.
		const replay = await fetch(`${base}/token`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: first.refresh_token,
				client_id: clientId,
			}),
		});
		expect(replay.status).toBe(400);

		// The new access token still opens a session.
		const session = await initializeSession(
			base,
			`Bearer ${second.access_token}`,
		);
		expect(session.status).toBe(200);
		await session.body?.cancel();
	});

	it("re-renders the consent page when Hevy rejects the key", async () => {
		const { base } = await startServer();
		const clientId = await registerClient(base);
		const pkce = createPkce();
		const authorizeUrl =
			`${base}/authorize?response_type=code&client_id=${clientId}` +
			`&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
			`&code_challenge=${pkce.challenge}&code_challenge_method=S256`;
		const html = await (await fetch(authorizeUrl)).text();
		const encoded = /name="oauth_request" value="([^"]+)"/u.exec(html)?.[1];

		const response = await fetch(`${base}/authorize`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				oauth_request: encoded as string,
				hevy_api_key: "wrong-key",
			}),
			redirect: "manual",
		});
		expect(response.status).toBe(401);
		expect(await response.text()).toContain("Hevy rejected this API key");
	});

	it("keeps one grant's session out of another grant's reach", async () => {
		const { base } = await startServer();
		const clientId = await registerClient(base);

		const firstPkce = createPkce();
		const firstTokens = (await (
			await exchangeCode(
				base,
				clientId,
				await authorize(base, clientId, firstPkce, VALID_KEY),
				firstPkce.verifier,
			)
		).json()) as TokenResponse;
		const secondPkce = createPkce();
		const secondTokens = (await (
			await exchangeCode(
				base,
				clientId,
				await authorize(base, clientId, secondPkce, OTHER_KEY),
				secondPkce.verifier,
			)
		).json()) as TokenResponse;

		const session = await initializeSession(
			base,
			`Bearer ${firstTokens.access_token}`,
		);
		const sessionId = session.headers.get("mcp-session-id") as string;
		await session.body?.cancel();

		// The second grant knows the session id but must not be able to drive it.
		const stolen = await fetch(`${base}/mcp`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json, text/event-stream",
				Authorization: `Bearer ${secondTokens.access_token}`,
				"Mcp-Session-Id": sessionId,
			},
			body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
		});
		expect(stolen.status).toBe(404);
	});

	it("accepts a direct Hevy API key only when that is enabled", async () => {
		const guarded = await startServer();
		const refused = await initializeSession(
			guarded.base,
			`Bearer ${VALID_KEY}`,
		);
		expect(refused.status).toBe(401);

		const permissive = await startServer({ allowDirectApiKeyBearer: true });
		const accepted = await initializeSession(
			permissive.base,
			`Bearer ${VALID_KEY}`,
		);
		expect(accepted.status).toBe(200);
		expect(permissive.apiKeys).toEqual([VALID_KEY]);
		await accepted.body?.cancel();
	});

	it("advertises the public origin and pins Host behind a TLS proxy", async () => {
		// A hosted platform terminates TLS and forwards the request over plain
		// HTTP to a local port, keeping the public hostname in `Host`. Node's
		// fetch refuses to send a `Host` header, so drive this one over
		// `node:http` to reproduce what the proxy actually sends.
		const hostname = "hevy-mcp.example.com";
		const publicOrigin = `https://${hostname}`;
		const { base } = await startServer({ publicOrigin });
		const port = Number(new URL(base).port);

		const proxied = (
			path: string,
			headers: Record<string, string> = {},
		): Promise<{
			status: number;
			headers: NodeJS.Dict<string | string[]>;
			body: string;
		}> =>
			new Promise((resolve, reject) => {
				const client = httpRequest(
					{
						host: "127.0.0.1",
						port,
						path,
						method: "POST",
						headers: {
							Host: hostname,
							"X-Forwarded-Proto": "https",
							"Content-Type": "application/json",
							...headers,
						},
					},
					(response) => {
						let body = "";
						response.setEncoding("utf8");
						response.on("data", (chunk: string) => {
							body += chunk;
						});
						response.on("end", () =>
							resolve({
								status: response.statusCode ?? 0,
								headers: response.headers,
								body,
							}),
						);
					},
				);
				client.once("error", reject);
				client.end("{}");
			});

		// The request reaches the auth layer rather than being turned away by
		// the Host check, and the challenge names the public URL.
		const challenged = await proxied("/mcp");
		expect(challenged.status).toBe(401);
		expect(String(challenged.headers["www-authenticate"])).toContain(
			`${publicOrigin}/.well-known/oauth-protected-resource/mcp`,
		);

		// A request carrying somebody else's Host is refused.
		const foreign = await proxied("/mcp", { Host: "attacker.example" });
		expect(foreign.status).toBe(403);

		const metadata = (await (
			await fetch(`${base}/.well-known/oauth-authorization-server`)
		).json()) as { issuer: string; token_endpoint: string };
		expect(metadata.issuer).toBe(publicOrigin);
		expect(metadata.token_endpoint).toBe(`${publicOrigin}/token`);
	});

	it("completes consent from a sandboxed browser context", async () => {
		// Claude renders the consent page in a sandboxed context, so the form
		// submission carries the opaque origin "null" rather than a nameable one.
		const { base } = await startServer();
		const clientId = await registerClient(base);
		const pkce = createPkce();
		const authorizeUrl =
			`${base}/authorize?response_type=code&client_id=${clientId}` +
			`&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
			`&code_challenge=${pkce.challenge}&code_challenge_method=S256&state=st`;
		const html = await (await fetch(authorizeUrl)).text();
		const encoded = /name="oauth_request" value="([^"]+)"/u.exec(html)?.[1];

		const submitted = await fetch(`${base}/authorize`, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Origin: "null",
			},
			body: new URLSearchParams({
				oauth_request: encoded as string,
				hevy_api_key: VALID_KEY,
			}),
			redirect: "manual",
		});
		expect(submitted.status).toBe(302);
		// The opaque origin must not be echoed back: doing so would let any
		// sandboxed document read the redirect carrying the authorization code.
		expect(submitted.headers.get("access-control-allow-origin")).toBeNull();

		const location = new URL(submitted.headers.get("location") as string);
		const code = location.searchParams.get("code") as string;
		const tokens = (await (
			await exchangeCode(base, clientId, code, pkce.verifier)
		).json()) as TokenResponse;
		expect(tokens.access_token.split(":")).toHaveLength(3);
	});

	it("keeps the opaque-origin exception off the MCP endpoint", async () => {
		// The exception exists only so the consent form can be submitted. A
		// sandboxed document must never reach the MCP endpoint through it.
		const { base } = await startServer();
		const response = await fetch(`${base}/mcp`, {
			method: "POST",
			headers: { "Content-Type": "application/json", Origin: "null" },
			body: "{}",
		});
		expect(response.status).toBe(403);
	});

	it("still refuses a named origin that is not allowlisted on consent", async () => {
		const { base } = await startServer();
		const response = await fetch(`${base}/authorize`, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Origin: "https://evil.example",
			},
			body: new URLSearchParams({ oauth_request: "x", hevy_api_key: "y" }),
			redirect: "manual",
		});
		expect(response.status).toBe(403);
	});

	it("refuses to register a redirect URI that is not https or loopback", async () => {
		const { base } = await startServer();
		const response = await fetch(`${base}/register`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ redirect_uris: ["http://evil.example/cb"] }),
		});
		expect(response.status).toBe(400);
		expect((await response.json()) as { error: string }).toMatchObject({
			error: "invalid_redirect_uri",
		});
	});
});
