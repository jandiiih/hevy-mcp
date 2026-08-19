/**
 * CORS handling for the Node HTTP transport.
 *
 * Browser-based MCP clients (Claude.ai custom connectors, ChatGPT connectors,
 * the web editors) issue cross-origin requests and a preflight for anything
 * carrying `Authorization`. Without an explicit allowlist the browser refuses
 * the exchange before the transport ever sees it. Non-browser clients send no
 * `Origin` header at all and are unaffected by everything here.
 *
 * The allowlist mirrors the Cloudflare Worker's `DEFAULT_ALLOWED_ORIGINS` so
 * both adapters accept the same clients.
 */

const ALLOWED_ORIGINS_ENV = "HEVY_MCP_ALLOWED_ORIGINS";
const DISABLE_ORIGIN_CHECK_ENV = "HEVY_MCP_DISABLE_ORIGIN_CHECK";

export const DEFAULT_ALLOWED_ORIGINS = [
	"https://claude.ai", // Anthropic Claude web connector
	"https://www.claude.ai", // Anthropic Claude web connector
	"https://claude.com", // Anthropic Claude web connector
	"https://www.claude.com", // Anthropic Claude web connector
	"https://chatgpt.com", // OpenAI ChatGPT connectors
	"https://chat.openai.com", // Legacy ChatGPT web origin
	"https://vscode.dev", // VS Code for the Web
	"https://github.dev", // github.dev web editor
] as const;

/** Request headers a browser MCP client sends and must be allowed to send. */
const ALLOWED_HEADERS = [
	"Authorization",
	"Content-Type",
	"Accept",
	"Last-Event-ID",
	"MCP-Protocol-Version",
	"Mcp-Session-Id",
].join(", ");

/**
 * Response headers a browser MCP client must be able to read. `Mcp-Session-Id`
 * carries the session handle from the initialize response; without exposing it
 * the client cannot make any follow-up request. `WWW-Authenticate` carries the
 * OAuth resource-metadata pointer that starts the authorization flow.
 */
const EXPOSED_HEADERS = ["Mcp-Session-Id", "WWW-Authenticate"].join(", ");

const ALLOWED_METHODS = "GET, POST, DELETE, OPTIONS";
const PREFLIGHT_MAX_AGE_SECONDS = "86400";

/**
 * The parts of a request these helpers read. Declaring the contract
 * structurally rather than depending on the full `IncomingMessage` keeps the
 * CORS rules independent of the HTTP server implementation and directly
 * testable without constructing a socket.
 */
export interface CorsRequest {
	readonly headers: Readonly<Record<string, string | string[] | undefined>>;
	readonly method?: string;
}

/** The parts of a response these helpers write. */
export interface CorsResponse {
	readonly headersSent: boolean;
	readonly destroyed: boolean;
	statusCode: number;
	setHeader(name: string, value: string): unknown;
	appendHeader?(name: string, value: string): unknown;
	end(): unknown;
}

export interface CorsPolicy {
	/** Exact origins accepted from browser clients. */
	allowedOrigins: ReadonlySet<string>;
	/** Development escape hatch; never enable on a public deployment. */
	allowAnyOrigin: boolean;
}

export function parseAllowedOrigins(value: string | undefined): Set<string> {
	const origins =
		value === undefined || value.trim() === ""
			? DEFAULT_ALLOWED_ORIGINS
			: value.split(",");
	return new Set(origins.map((origin) => origin.trim()).filter(Boolean));
}

export function resolveCorsPolicy(
	env: NodeJS.ProcessEnv = process.env,
): CorsPolicy {
	return {
		allowedOrigins: parseAllowedOrigins(env[ALLOWED_ORIGINS_ENV]),
		allowAnyOrigin:
			env[DISABLE_ORIGIN_CHECK_ENV]?.trim().toLowerCase() === "true",
	};
}

export type OriginDecision =
	| { kind: "absent" }
	| { kind: "allowed"; origin: string }
	| { kind: "rejected"; origin: string };

/**
 * Classify a request's `Origin`. Same-origin requests are always allowed:
 * a client that already reached this exact origin gains nothing from CORS.
 */
export function evaluateOrigin(
	request: CorsRequest,
	policy: CorsPolicy,
	publicOrigin?: string,
): OriginDecision {
	const header = request.headers.origin;
	const origin = Array.isArray(header) ? header[0] : header;
	if (!origin) return { kind: "absent" };
	if (policy.allowAnyOrigin) return { kind: "allowed", origin };
	if (publicOrigin && origin === publicOrigin) {
		return { kind: "allowed", origin };
	}
	return policy.allowedOrigins.has(origin)
		? { kind: "allowed", origin }
		: { kind: "rejected", origin };
}

/**
 * Apply CORS response headers for an allowed origin. `Vary: Origin` keeps any
 * intermediary cache from serving one origin's response to another.
 */
export function applyCorsHeaders(
	response: CorsResponse,
	decision: OriginDecision,
): void {
	if (response.headersSent || response.destroyed) return;
	response.appendHeader?.("Vary", "Origin");
	if (decision.kind !== "allowed") return;
	response.setHeader("Access-Control-Allow-Origin", decision.origin);
	response.setHeader("Access-Control-Expose-Headers", EXPOSED_HEADERS);
}

/**
 * Answer a CORS preflight. Returns true when the request was handled and the
 * caller must not process it further.
 */
export function handlePreflight(
	request: CorsRequest,
	response: CorsResponse,
	decision: OriginDecision,
): boolean {
	if (request.method !== "OPTIONS") return false;
	applyCorsHeaders(response, decision);
	if (decision.kind === "rejected") {
		response.statusCode = 403;
		response.end();
		return true;
	}
	response.setHeader("Access-Control-Allow-Methods", ALLOWED_METHODS);
	response.setHeader("Access-Control-Allow-Headers", ALLOWED_HEADERS);
	response.setHeader("Access-Control-Max-Age", PREFLIGHT_MAX_AGE_SECONDS);
	response.statusCode = 204;
	response.end();
	return true;
}
