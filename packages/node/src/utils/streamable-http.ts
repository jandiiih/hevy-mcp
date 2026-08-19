import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import {
	createServer,
	type IncomingMessage,
	type Server,
	type ServerResponse,
} from "node:http";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { z } from "zod";
import {
	createExecutionProjection,
	createSafeErrorDiagnostic,
} from "@hevy-mcp/core";
import type { NodeCliOptions } from "./arguments.js";
import {
	applyCorsHeaders,
	evaluateOrigin,
	handlePreflight,
	isOpaqueOrigin,
	resolveCorsPolicy,
	type CorsPolicy,
	type OriginDecision,
} from "./http-cors.js";
import { resolvePublicOrigin } from "./http-public-url.js";
import type { HevyOAuthProvider } from "./oauth/index.js";
import { AUTHORIZE_PATH, hasCredentialFormat } from "./oauth/index.js";
import { httpAdmissionRejections, httpSessionEvictions } from "./metrics.js";
import {
	runWithMcpSessionContext,
	createMcpSessionContext,
	recordMcpSessionStart,
	recordMcpSessionTermination,
	resolveSessionTerminationCategory,
	type McpSessionContext,
} from "./mcp-session-observability.js";

const stringSchema = z.string();
const numberSchema = z.number();
const objectSchema = z.object({}).passthrough();

function isString<T>(value: T): value is T & string {
	return stringSchema.safeParse(value).success;
}

function isNumber<T>(value: T): value is T & number {
	return numberSchema.safeParse(value).success;
}

function isObject<T>(value: T): value is T & object {
	return objectSchema.safeParse(value).success;
}

/**
 * The MCP endpoint. `/mcp` is the canonical path that remote clients and the
 * Cloudflare Worker use; `/mcp-v1` stays served so deployments already
 * configured against it keep working.
 */
export const MCP_PATH = "/mcp";
const MCP_PATH_ALIASES = [MCP_PATH, "/mcp-v1"] as const;
/** Liveness endpoint for platform health checks; exposes no account data. */
const HEALTH_PATH = "/healthz";
const MAX_BODY_BYTES = 1_048_576;
const HTTP_BEARER_TOKEN = "HEVY_MCP_HTTP_BEARER_TOKEN";

const HTTP_ADMISSION_DEFAULTS = {
	maxSessions: 100,
	maxInitializing: 10,
	idleTimeoutMs: 30 * 60 * 1000,
	bodyTimeoutMs: 30 * 1000,
} as const;
const HTTP_ADMISSION_LIMITS = {
	maxSessions: 10_000,
	maxInitializing: 1_000,
	idleTimeoutMs: 24 * 60 * 60 * 1000,
	bodyTimeoutMs: 5 * 60 * 1000,
} as const;

export interface HttpAdmissionConfig {
	maxSessions: number;
	maxInitializing: number;
	idleTimeoutMs: number;
	bodyTimeoutMs: number;
}

function parsePositiveLimit<T>(
	value: T,
	fallback: number,
	maximum: number,
): number {
	const parsed = isNumber(value) ? value : Number(value);
	if (!Number.isFinite(parsed) || parsed < 1) return fallback;
	return Math.min(Math.floor(parsed), maximum);
}

function envLimit(name: string, fallback: number, maximum: number): number {
	return parsePositiveLimit(process.env[name], fallback, maximum);
}

export function resolveHttpAdmissionConfig(
	overrides: Partial<HttpAdmissionConfig> = {},
): HttpAdmissionConfig {
	return {
		maxSessions: parsePositiveLimit(
			overrides.maxSessions ??
				envLimit(
					"HEVY_MCP_HTTP_MAX_SESSIONS",
					HTTP_ADMISSION_DEFAULTS.maxSessions,
					HTTP_ADMISSION_LIMITS.maxSessions,
				),
			HTTP_ADMISSION_DEFAULTS.maxSessions,
			HTTP_ADMISSION_LIMITS.maxSessions,
		),
		maxInitializing: parsePositiveLimit(
			overrides.maxInitializing ??
				envLimit(
					"HEVY_MCP_HTTP_MAX_INITIALIZING",
					HTTP_ADMISSION_DEFAULTS.maxInitializing,
					HTTP_ADMISSION_LIMITS.maxInitializing,
				),
			HTTP_ADMISSION_DEFAULTS.maxInitializing,
			HTTP_ADMISSION_LIMITS.maxInitializing,
		),
		idleTimeoutMs: parsePositiveLimit(
			overrides.idleTimeoutMs ??
				envLimit(
					"HEVY_MCP_HTTP_IDLE_TIMEOUT_MS",
					HTTP_ADMISSION_DEFAULTS.idleTimeoutMs,
					HTTP_ADMISSION_LIMITS.idleTimeoutMs,
				),
			HTTP_ADMISSION_DEFAULTS.idleTimeoutMs,
			HTTP_ADMISSION_LIMITS.idleTimeoutMs,
		),
		bodyTimeoutMs: parsePositiveLimit(
			overrides.bodyTimeoutMs ??
				envLimit(
					"HEVY_MCP_HTTP_BODY_TIMEOUT_MS",
					HTTP_ADMISSION_DEFAULTS.bodyTimeoutMs,
					HTTP_ADMISSION_LIMITS.bodyTimeoutMs,
				),
			HTTP_ADMISSION_DEFAULTS.bodyTimeoutMs,
			HTTP_ADMISSION_LIMITS.bodyTimeoutMs,
		),
	};
}

type HttpTransport = NodeStreamableHTTPServerTransport;
export interface OwnedMcpServer {
	connect(transport: HttpTransport): Promise<void>;
	close(): Promise<void>;
}

export type McpServerFactory = (params: {
	apiKey: string;
	lifecycleSignal?: AbortSignal;
}) => Promise<OwnedMcpServer>;

interface HttpSession {
	transport: HttpTransport;
	server: OwnedMcpServer;
	context: McpSessionContext;
	lifecycleController: AbortController;
	responses: Set<ServerResponse>;
	/**
	 * Opaque identity of whoever initialized this session. Every follow-up
	 * request must present the same identity, so a leaked session id cannot be
	 * driven by a different OAuth grant or API key.
	 */
	principal: string;
	idleTimer?: ReturnType<typeof setTimeout>;
	closed: boolean;
}

/**
 * Optional capabilities layered on top of the base transport. They are all
 * inert unless a caller supplies them, so loopback and Docker deployments
 * behave exactly as before.
 */
export interface HttpServerExtensions {
	/** When present, the MCP endpoint is guarded by OAuth 2.1. */
	oauth?: HevyOAuthProvider;
	/** Origin allowlist for browser clients. Defaults to the built-in list. */
	cors?: CorsPolicy;
	/** Public origin behind a proxy; also pins the accepted Host header. */
	publicOrigin?: string;
	/**
	 * Accept a raw Hevy API key as the bearer value. Lets non-browser clients
	 * skip the OAuth dance on a deployment that has OAuth enabled.
	 */
	allowDirectApiKeyBearer?: boolean;
}

/** Identity and Hevy credential resolved for one request. */
interface RequestCredential {
	apiKey: string;
	principal: string;
}

export interface HttpServerHandle {
	close(): Promise<void>;
	server: Server;
}

class HttpRequestError extends Error {
	readonly statusCode: number;

	constructor(statusCode: number, message: string) {
		super(message);
		this.name = "HttpRequestError";
		this.statusCode = statusCode;
	}
}

function normalizeHost(host: string): string {
	return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function isLoopbackHost(host: string): boolean {
	const normalized = normalizeHost(host).toLowerCase();
	return (
		normalized === "localhost" ||
		normalized === "127.0.0.1" ||
		normalized === "::1"
	);
}

function hostNamesFor(options: NodeCliOptions): Set<string> {
	const configured = normalizeHost(options.host).toLowerCase();
	const names = new Set([configured]);
	if (isLoopbackHost(options.host)) {
		names.add("localhost");
		names.add("127.0.0.1");
		names.add("::1");
	}
	return names;
}

function expectedPort(options: NodeCliOptions, server: Server): number {
	if (options.port !== 0) return options.port;
	const address = server.address();
	return address && !isString(address) ? address.port : 0;
}

function validateHostHeader(
	request: IncomingMessage,
	allowedHosts: Set<string>,
	port: number,
	allowAnyHostname = false,
): boolean {
	const header = request.headers.host;
	if (!header || Array.isArray(header)) return false;
	try {
		const parsed = new URL(`http://${header}`);
		if (
			parsed.username ||
			parsed.password ||
			parsed.pathname !== "/" ||
			parsed.search ||
			parsed.hash ||
			(!allowAnyHostname && (parsed.port ? Number(parsed.port) : 80) !== port)
		) {
			return false;
		}
		return (
			allowAnyHostname ||
			allowedHosts.has(normalizeHost(parsed.hostname).toLowerCase())
		);
	} catch {
		return false;
	}
}

function safeDiagnostic<T>(error: T): string {
	return JSON.stringify(createSafeErrorDiagnostic(error));
}

function writeJson(res: ServerResponse, status: number, message: string): void {
	if (res.headersSent || res.destroyed) return;
	res.statusCode = status;
	res.setHeader("Content-Type", "application/json");
	res.end(JSON.stringify({ error: message }));
}

function writeExecutionJson<T>(
	res: ServerResponse,
	status: number,
	message: string,
	error: T,
): void {
	if (res.headersSent || res.destroyed) return;
	const diagnostic = createSafeErrorDiagnostic(error);
	const execution = createExecutionProjection(diagnostic);
	res.statusCode = status;
	res.setHeader("Content-Type", "application/json");
	res.end(
		JSON.stringify({
			error: { message, ...execution },
		}),
	);
}

interface ReadBodyHandlers {
	onData: (chunk: Buffer | string) => void;
	onError: (error: Error) => void;
	onAbort: () => void;
	onEnd: () => void;
	onTimeout: () => void;
}

interface RejectBeforeBodyHandlers {
	onError: () => void;
}

function readBody(
	request: IncomingMessage,
	timeoutMs: number,
	signal?: AbortSignal,
): Promise<unknown> {
	return new Promise((resolve, reject) => {
		let size = 0;
		let settled = false;
		const chunks: Buffer[] = [];
		const handlers: ReadBodyHandlers = {
			onData: () => {},
			onError: () => {},
			onAbort: () => {},
			onEnd: () => {},
			onTimeout: () => {},
		};
		const timer = setTimeout(() => handlers.onTimeout(), timeoutMs);
		const removeErrorListenerAfterDrain = () => {
			request.removeListener("error", handlers.onError);
		};
		const cleanup = (retainErrorListener = false) => {
			clearTimeout(timer);
			request.removeListener("data", handlers.onData);
			request.removeListener("end", handlers.onEnd);
			if (retainErrorListener) {
				request.once("close", removeErrorListenerAfterDrain);
			} else {
				request.removeListener("error", handlers.onError);
			}
			signal?.removeEventListener("abort", handlers.onAbort);
		};
		const settle = (callback: () => void, retainErrorListener = false) => {
			if (settled) return;
			settled = true;
			cleanup(retainErrorListener);
			callback();
		};
		const rejectAndDrain = (error: HttpRequestError) => {
			if (settled) return;
			settled = true;
			cleanup(true);
			request.resume();
			reject(error);
		};
		handlers.onData = (chunk: Buffer | string) => {
			const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			size += buffer.byteLength;
			if (size > MAX_BODY_BYTES) {
				rejectAndDrain(new HttpRequestError(413, "Request body is too large."));
				return;
			}
			if (!settled) chunks.push(buffer);
		};
		handlers.onError = (error: Error) => settle(() => reject(error));
		handlers.onAbort = () =>
			rejectAndDrain(
				new HttpRequestError(
					503,
					"HTTP server is shutting down. Retry shortly.",
				),
			);
		handlers.onEnd = () =>
			settle(() => {
				try {
					const raw = Buffer.concat(chunks).toString("utf8");
					resolve(raw.length === 0 ? undefined : JSON.parse(raw));
				} catch {
					reject(new HttpRequestError(400, "Request body must be valid JSON."));
				}
			});
		handlers.onTimeout = () =>
			rejectAndDrain(new HttpRequestError(408, "Request body timed out."));
		request.on("data", handlers.onData);
		request.once("error", handlers.onError);
		request.once("end", handlers.onEnd);
		signal?.addEventListener("abort", handlers.onAbort, { once: true });
		timer.unref?.();
		if (signal?.aborted) handlers.onAbort();
	});
}

function isInitializeRequest<T>(body: T): boolean {
	return Boolean(
		body &&
		isObject(body) &&
		!Array.isArray(body) &&
		"method" in body &&
		body.method === "initialize",
	);
}

function closeServer(server: Server): Promise<void> {
	return new Promise((resolve, reject) => {
		if (!server.listening) {
			resolve();
			return;
		}
		server.close((error) => (error ? reject(error) : resolve()));
		server.closeIdleConnections();
		server.closeAllConnections();
	});
}

/** Extract the bearer value from an Authorization header, if well-formed. */
function parseBearer(request: IncomingMessage): string | null {
	const header = request.headers.authorization;
	if (!isString(header)) return null;
	const match = /^Bearer ([^\s,]+)$/iu.exec(header);
	return match?.[1] ?? null;
}

function isBearerAuthorized(
	request: IncomingMessage,
	token: string | undefined,
): boolean {
	if (!token) return false;
	const header = request.headers.authorization;
	if (!isString(header)) return false;
	const expected = Buffer.from(`Bearer ${token}`);
	const actual = Buffer.from(header);
	return (
		expected.byteLength === actual.byteLength &&
		timingSafeEqual(expected, actual)
	);
}

function aggregateErrors<T>(errors: T[], message: string): T | AggregateError {
	if (errors.length === 1) return errors[0];
	return new AggregateError(errors, message);
}

function recordHttpAdmissionRejection(
	reason: "shutting_down" | "initializing_capacity" | "session_capacity",
): void {
	try {
		httpAdmissionRejections.add(1, { reason });
	} catch {
		// Optional telemetry must never affect admission behavior.
	}
}

function recordHttpSessionEviction(): void {
	try {
		httpSessionEvictions.add(1, { reason: "idle" });
	} catch {
		// Optional telemetry must never affect cleanup behavior.
	}
}

function rejectBeforeBody(
	request: IncomingMessage,
	response: ServerResponse,
	status: number,
	message: string,
	timeoutMs: number,
): void {
	const handlers: RejectBeforeBodyHandlers = { onError: () => {} };
	const timer = setTimeout(() => request.destroy(), timeoutMs);
	const cleanup = () => {
		clearTimeout(timer);
		request.removeListener("error", handlers.onError);
		request.removeListener("close", cleanup);
	};
	handlers.onError = () => cleanup();
	request.once("error", handlers.onError);
	request.once("close", cleanup);
	timer.unref?.();
	request.resume();
	writeJson(response, status, message);
}

export function isHttpHostAllowed(host: string): boolean {
	return isLoopbackHost(host);
}

function requestPathname(request: IncomingMessage): string {
	return request.url?.split("?", 1)[0] ?? "/";
}

function isMcpPath(pathname: string): boolean {
	return MCP_PATH_ALIASES.some((alias) => alias === pathname);
}

export async function startStreamableHttpServer(
	options: NodeCliOptions,
	apiKey: string,
	createMcpServer: McpServerFactory,
	configOverrides: Partial<HttpAdmissionConfig> = {},
	extensions: HttpServerExtensions = {},
): Promise<HttpServerHandle> {
	const config = resolveHttpAdmissionConfig(configOverrides);
	const wildcard =
		options.host === "0.0.0.0" ||
		options.host === "::" ||
		options.host === "[::]";
	const loopback = isLoopbackHost(options.host);
	const oauth = extensions.oauth;
	const corsPolicy = extensions.cors ?? resolveCorsPolicy();
	const configuredOrigin = extensions.publicOrigin;
	const bearerToken = process.env[HTTP_BEARER_TOKEN];
	// OAuth authenticates every request against a per-user grant, so it fully
	// replaces the shared static token as the non-loopback protection.
	if (!loopback && !bearerToken && !oauth) {
		throw new Error(
			`Non-loopback HTTP mode requires ${HTTP_BEARER_TOKEN} or OAuth (${"HEVY_MCP_OAUTH"}=1) to protect the shared Hevy account.`,
		);
	}

	const sessions = new Map<string, HttpSession>();
	const pendingSessions = new Set<HttpSession>();
	const initializationControllers = new Set<AbortController>();
	const initializationPromises = new Set<Promise<void>>();
	const cleanupErrors: unknown[] = [];
	let shuttingDown = false;
	const server = createServer((request, response) => {
		void handleRequest(request, response).catch((error) => {
			if (response.headersSent || response.destroyed) {
				if (!response.writableEnded) response.destroy();
				return;
			}
			if (error instanceof HttpRequestError) {
				writeJson(response, error.statusCode, error.message);
				return;
			}
			console.error(`HTTP request failed: ${safeDiagnostic(error)}`);
			writeExecutionJson(response, 500, "Internal server error.", error);
		});
	});

	function armIdleTimer(session: HttpSession): void {
		if (session.closed) return;
		if (session.idleTimer) clearTimeout(session.idleTimer);
		session.idleTimer = setTimeout(() => {
			const hasActiveResponse = [...session.responses].some(
				(response) => !response.writableEnded,
			);
			if (hasActiveResponse) {
				armIdleTimer(session);
				return;
			}
			recordHttpSessionEviction();
			closeSession(session).catch((error) => {
				cleanupErrors.push(error);
			});
		}, config.idleTimeoutMs);
		session.idleTimer.unref?.();
	}

	async function closeSession(
		session: HttpSession,
		failureCategory?: "connect_failure" | "startup_failure" | "unknown",
	): Promise<void> {
		if (session.closed) return;
		session.closed = true;
		if (session.idleTimer) {
			clearTimeout(session.idleTimer);
			session.idleTimer = undefined;
		}
		pendingSessions.delete(session);
		for (const [id, current] of sessions) {
			if (current === session) sessions.delete(id);
		}
		for (const response of session.responses) {
			if (!response.writableEnded) response.destroy();
		}
		// The SDK transport closes response streams, but its stateful close path
		// does not abort the request signal already handed to MCP handlers. Abort
		// the session-owned lifecycle signal first so active Hevy calls stop too.
		session.lifecycleController.abort(
			new DOMException("MCP session closed", "AbortError"),
		);

		const results = await Promise.allSettled([
			Promise.resolve().then(() => session.transport.close()),
			Promise.resolve().then(() => session.server.close()),
		]);
		const errors = results.flatMap((result) =>
			result.status === "rejected" ? [result.reason] : [],
		);
		const succeeded = errors.length === 0;
		recordMcpSessionTermination(
			failureCategory && succeeded
				? failureCategory
				: resolveSessionTerminationCategory(succeeded, session.context),
			session.context,
		);
		if (errors.length > 0) {
			throw aggregateErrors(errors, "MCP session cleanup failed.");
		}
	}

	async function closeUnregistered(
		transport: HttpTransport,
		mcpServer: OwnedMcpServer | undefined,
	): Promise<void> {
		const results = await Promise.allSettled([
			Promise.resolve().then(() => transport.close()),
			...(mcpServer ? [Promise.resolve().then(() => mcpServer.close())] : []),
		]);
		const errors = results.flatMap((result) =>
			result.status === "rejected" ? [result.reason] : [],
		);
		if (errors.length > 0) throw aggregateErrors(errors, "MCP cleanup failed.");
		return;
	}

	function trackSessionResponse(
		session: HttpSession,
		response: ServerResponse,
	): void {
		session.responses.add(response);
		response.once("close", () => {
			session.responses.delete(response);
			// A destroyed response means the client disconnected before the
			// exchange completed. The SDK does not expose a request-scoped signal
			// for this transport, so evict and close the whole session rather than
			// leaving an aborted session reusable or poisoning future requests.
			if (!response.writableEnded && !session.closed) {
				closeSession(session).catch((error) => {
					cleanupErrors.push(error);
				});
			} else if (!session.closed) {
				armIdleTimer(session);
			}
		});
	}

	interface RequestSessionResolution {
		sessionId?: string;
		existingSession?: HttpSession;
		trackedExistingResponse: boolean;
		credential: RequestCredential;
	}

	/** Origin a client used to reach this request, for OAuth metadata URLs. */
	function publicOriginFor(request: IncomingMessage): string {
		return (
			resolvePublicOrigin(request, { configuredOrigin }) ??
			`http://${options.host}:${expectedPort(options, server)}`
		);
	}

	/**
	 * Behind a proxy the Host header names the public hostname rather than the
	 * bind address, so the default wildcard check cannot pin it. When a public
	 * origin is configured, require the Host to match it; that restores DNS
	 * rebinding protection for a deployment that would otherwise accept any
	 * hostname.
	 */
	function hostHeaderAccepted(request: IncomingMessage): boolean {
		if (configuredOrigin) {
			const header = request.headers.host;
			if (!isString(header)) return false;
			try {
				const expectedHostname = new URL(configuredOrigin).hostname;
				const actual = new URL(`http://${header}`);
				return (
					!actual.username &&
					!actual.password &&
					actual.pathname === "/" &&
					!actual.search &&
					normalizeHost(actual.hostname).toLowerCase() ===
						normalizeHost(expectedHostname).toLowerCase()
				);
			} catch {
				return false;
			}
		}
		return validateHostHeader(
			request,
			hostNamesFor(options),
			expectedPort(options, server),
			wildcard,
		);
	}

	/**
	 * Resolve the Hevy credential for a request.
	 *
	 * With OAuth on, the key comes from the presented grant, so each session
	 * acts for the user that authorized it. Without OAuth the server keeps its
	 * previous single-key behavior behind the loopback or static-token gate.
	 */
	function resolveCredential(
		request: IncomingMessage,
		response: ServerResponse,
	): RequestCredential | undefined {
		if (!oauth) {
			if (!loopback && !isBearerAuthorized(request, bearerToken)) {
				writeJson(response, 401, "Authorization required");
				return undefined;
			}
			return { apiKey, principal: "static" };
		}

		const origin = publicOriginFor(request);
		const unauthorized = (description: string): undefined => {
			if (!response.headersSent && !response.destroyed) {
				response.setHeader(
					"WWW-Authenticate",
					oauth.unauthorizedHeader(origin, description),
				);
			}
			writeJson(response, 401, "Authorization required");
			return undefined;
		};

		const bearer = parseBearer(request);
		if (!bearer) return unauthorized("Authorization header is required");

		if (hasCredentialFormat(bearer)) {
			const result = oauth.authenticateBearer(bearer);
			if (result.kind === "rejected") return unauthorized(result.reason);
			return {
				apiKey: result.grant.apiKey,
				principal: `grant:${result.grant.grantId}`,
			};
		}
		if (!extensions.allowDirectApiKeyBearer) {
			return unauthorized("An OAuth access token is required");
		}
		// A raw Hevy API key. It is validated upstream when the session's MCP
		// server is built, so an invalid key fails the initialize call.
		const digest = createHash("sha256").update(bearer, "utf8").digest("hex");
		return { apiKey: bearer, principal: `key:${digest}` };
	}

	function resolveRequestSession(
		request: IncomingMessage,
		response: ServerResponse,
	): RequestSessionResolution | undefined {
		if (!hostHeaderAccepted(request)) {
			writeJson(response, 403, "Invalid Host header");
			return undefined;
		}
		const credential = resolveCredential(request, response);
		if (!credential) return undefined;

		const sessionHeader = request.headers["mcp-session-id"];
		const sessionId = isString(sessionHeader) ? sessionHeader : undefined;
		const existingSession = sessionId ? sessions.get(sessionId) : undefined;
		if (sessionId && !existingSession) {
			rejectBeforeBody(
				request,
				response,
				404,
				"Unknown Mcp-Session-Id.",
				config.bodyTimeoutMs,
			);
			return undefined;
		}
		if (existingSession && existingSession.principal !== credential.principal) {
			// The session id is valid but belongs to someone else. Report it as
			// unknown so the id itself is not confirmed to a probing caller.
			rejectBeforeBody(
				request,
				response,
				404,
				"Unknown Mcp-Session-Id.",
				config.bodyTimeoutMs,
			);
			return undefined;
		}
		if (existingSession && request.method !== "DELETE") {
			trackSessionResponse(existingSession, response);
			return {
				sessionId,
				existingSession,
				trackedExistingResponse: true,
				credential,
			};
		}
		return {
			sessionId,
			existingSession,
			trackedExistingResponse: false,
			credential,
		};
	}

	interface InitializationReservation {
		controller: AbortController;
		release: () => void;
	}

	function reserveInitialization(
		request: IncomingMessage,
		response: ServerResponse,
	): InitializationReservation | null {
		if (shuttingDown) {
			recordHttpAdmissionRejection("shutting_down");
			rejectBeforeBody(
				request,
				response,
				503,
				"HTTP server is shutting down. Retry shortly.",
				config.bodyTimeoutMs,
			);
			return null;
		}
		if (initializationControllers.size >= config.maxInitializing) {
			recordHttpAdmissionRejection("initializing_capacity");
			rejectBeforeBody(
				request,
				response,
				503,
				"MCP server is busy initializing sessions. Retry shortly.",
				config.bodyTimeoutMs,
			);
			return null;
		}
		if (sessions.size + initializationControllers.size >= config.maxSessions) {
			recordHttpAdmissionRejection("session_capacity");
			rejectBeforeBody(
				request,
				response,
				429,
				"MCP session capacity reached. Retry after an existing session closes.",
				config.bodyTimeoutMs,
			);
			return null;
		}

		const controller = new AbortController();
		initializationControllers.add(controller);
		let resolveInitialization!: () => void;
		const initializationComplete = new Promise<void>((resolve) => {
			resolveInitialization = resolve;
		});
		initializationPromises.add(initializationComplete);
		let released = false;
		const onResponseClose = () => {
			if (!response.writableEnded) {
				controller.abort(
					new DOMException("MCP initialization response closed", "AbortError"),
				);
			}
		};
		response.once("close", onResponseClose);
		return {
			controller,
			release: () => {
				if (released) return;
				released = true;
				response.removeListener("close", onResponseClose);
				initializationControllers.delete(controller);
				initializationPromises.delete(initializationComplete);
				resolveInitialization();
			},
		};
	}

	async function handleInitializedSession<T>(
		request: IncomingMessage,
		response: ServerResponse,
		body: T,
		reservation: InitializationReservation,
		credential: RequestCredential,
	): Promise<void> {
		const context = createMcpSessionContext(isObject(body) ? body : {}, "http");
		recordMcpSessionStart(isObject(body) ? body : {}, "http", context);
		let session: HttpSession | undefined;
		let mcpServer: OwnedMcpServer | undefined;
		let connected = false;
		const lifecycleController = reservation.controller;
		const transport = new NodeStreamableHTTPServerTransport({
			sessionIdGenerator: randomUUID,
			onsessioninitialized: (id) => {
				if (!session) return;
				if (shuttingDown || lifecycleController.signal.aborted) {
					closeSession(session).catch((error) => {
						cleanupErrors.push(error);
					});
					return;
				}
				sessions.set(id, session);
				pendingSessions.delete(session);
				initializationControllers.delete(lifecycleController);
				armIdleTimer(session);
			},
		});
		transport.onclose = () => {
			if (session) {
				closeSession(session).catch((error) => {
					cleanupErrors.push(error);
				});
			}
		};
		try {
			mcpServer = await createMcpServer({
				apiKey: credential.apiKey,
				lifecycleSignal: lifecycleController.signal,
			});
			if (shuttingDown || lifecycleController.signal.aborted) {
				await closeUnregistered(transport, mcpServer);
				recordMcpSessionTermination("startup_failure", context);
				return;
			}
			session = {
				transport,
				server: mcpServer,
				context,
				lifecycleController,
				responses: new Set(),
				principal: credential.principal,
				closed: false,
			};
			pendingSessions.add(session);
			await mcpServer.connect(transport);
			connected = true;
			if (shuttingDown || lifecycleController.signal.aborted) {
				await closeSession(session);
				return;
			}
			trackSessionResponse(session, response);
			await runWithMcpSessionContext(context, () =>
				transport.handleRequest(request, response, body),
			);
		} catch (error) {
			lifecycleController.abort(
				new DOMException("MCP session startup failed", "AbortError"),
			);
			console.error(`HTTP session request failed: ${safeDiagnostic(error)}`);
			let cleanupError: unknown;
			try {
				if (session) {
					await closeSession(
						session,
						connected ? "unknown" : "connect_failure",
					);
				} else {
					await closeUnregistered(transport, mcpServer);
					recordMcpSessionTermination("startup_failure", context);
				}
			} catch (cleanupFailure) {
				cleanupError = cleanupFailure;
				if (!session) recordMcpSessionTermination("unknown", context);
			}
			if (cleanupError) {
				console.error(`HTTP cleanup failed: ${safeDiagnostic(cleanupError)}`);
			}
			if (!response.writableEnded && !shuttingDown)
				writeExecutionJson(response, 500, "Internal server error.", error);
		}
	}

	async function handleInitializationRequest<T>(
		request: IncomingMessage,
		response: ServerResponse,
		body: T,
		sessionId: string | undefined,
		reservation: InitializationReservation | undefined,
		credential: RequestCredential,
	): Promise<boolean> {
		if (request.method !== "POST" || !isInitializeRequest(body)) return false;
		if (sessionId) {
			writeJson(
				response,
				400,
				"Initialization must not include Mcp-Session-Id.",
			);
			return true;
		}
		if (!reservation) {
			writeJson(
				response,
				503,
				"MCP initialization capacity is unavailable. Retry shortly.",
			);
			return true;
		}
		await handleInitializedSession(
			request,
			response,
			body,
			reservation,
			credential,
		);
		return true;
	}

	async function handleExistingSessionRequest<T>(
		request: IncomingMessage,
		response: ServerResponse,
		body: T,
		sessionId: string | undefined,
		existingSession: HttpSession | undefined,
		trackedExistingResponse: boolean,
	): Promise<void> {
		if (!sessionId) {
			writeJson(response, 400, "Mcp-Session-Id header is required.");
			return;
		}
		const session = existingSession ?? sessions.get(sessionId);
		if (!session) {
			writeJson(response, 404, "Unknown Mcp-Session-Id.");
			return;
		}
		armIdleTimer(session);
		if (request.method !== "DELETE" && !trackedExistingResponse) {
			trackSessionResponse(session, response);
		}
		await runWithMcpSessionContext(session.context, () =>
			session.transport.handleRequest(request, response, body),
		);
		if (request.method === "DELETE" && !session.closed) {
			try {
				await closeSession(session);
			} catch (error) {
				cleanupErrors.push(error);
			}
		}
	}

	/**
	 * Handle everything that is not an MCP exchange: CORS preflight, the health
	 * probe, OAuth endpoints, and unknown paths. Returns true when the request
	 * has been answered.
	 */
	async function handleNonMcpRequest(
		request: IncomingMessage,
		response: ServerResponse,
		pathname: string,
		originDecision: OriginDecision,
	): Promise<boolean> {
		if (handlePreflight(request, response, originDecision)) return true;
		if (originDecision.kind === "rejected") {
			// The consent form is submitted from whatever browser context the MCP
			// client opened the authorization page in, and a sandboxed context
			// serializes its origin as the opaque value "null". Refusing that would
			// make the flow impossible to complete from such a client. The
			// submission is a top-level navigation carrying a user-typed key, and
			// it receives no CORS headers back, so an opaque-origin document still
			// cannot read the result. Keep this route-specific: it must never
			// extend to the MCP endpoint.
			const isConsentSubmission =
				oauth !== undefined &&
				request.method === "POST" &&
				pathname === AUTHORIZE_PATH;
			if (!isConsentSubmission || !isOpaqueOrigin(originDecision)) {
				console.error(
					`Rejected browser origin ${JSON.stringify(originDecision.origin)} for ${request.method} ${pathname}`,
				);
				writeJson(response, 403, "Origin not allowed");
				return true;
			}
		}
		if (pathname === HEALTH_PATH) {
			if (!response.headersSent && !response.destroyed) {
				response.statusCode = 200;
				response.setHeader("Content-Type", "application/json");
				response.setHeader("Cache-Control", "no-store");
				response.end(JSON.stringify({ status: "ok" }));
			}
			return true;
		}
		if (oauth?.handlesPath(pathname)) {
			await oauth.handleRequest(
				request,
				response,
				pathname,
				publicOriginFor(request),
			);
			return true;
		}
		if (!isMcpPath(pathname)) {
			writeJson(response, 404, "Not found");
			return true;
		}
		return false;
	}

	async function handleRequest(
		request: IncomingMessage,
		response: ServerResponse,
	): Promise<void> {
		let releaseInitialization: (() => void) | undefined;
		try {
			const pathname = requestPathname(request);
			const originDecision = evaluateOrigin(
				request,
				corsPolicy,
				configuredOrigin,
			);
			applyCorsHeaders(response, originDecision);
			if (
				await handleNonMcpRequest(request, response, pathname, originDecision)
			) {
				return;
			}
			const resolution = resolveRequestSession(request, response);
			if (!resolution) return;
			const requiresInitialization =
				request.method === "POST" && !resolution.sessionId;
			const reservation = requiresInitialization
				? reserveInitialization(request, response)
				: undefined;
			if (requiresInitialization && !reservation) return;
			releaseInitialization = reservation?.release;
			const body =
				request.method === "POST"
					? await readBody(
							request,
							config.bodyTimeoutMs,
							reservation?.controller.signal ??
								resolution.existingSession?.lifecycleController.signal,
						)
					: undefined;
			if (shuttingDown) {
				writeJson(
					response,
					503,
					"HTTP server is shutting down. Retry shortly.",
				);
				return;
			}
			if (
				await handleInitializationRequest(
					request,
					response,
					body,
					resolution.sessionId,
					reservation ?? undefined,
					resolution.credential,
				)
			)
				return;
			await handleExistingSessionRequest(
				request,
				response,
				body,
				resolution.sessionId,
				resolution.existingSession,
				resolution.trackedExistingResponse,
			);
		} finally {
			releaseInitialization?.();
		}
	}

	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(options.port, options.host, () => {
			server.removeListener("error", reject);
			resolve();
		});
	});

	let closePromise: Promise<void> | undefined;
	return {
		server,
		close: () => {
			if (closePromise) return closePromise;
			closePromise = (async () => {
				shuttingDown = true;
				for (const controller of initializationControllers) {
					controller.abort(
						new DOMException("HTTP server is shutting down", "AbortError"),
					);
				}
				const sessionsToClose = [
					...new Set([...sessions.values(), ...pendingSessions]),
				];
				const results = await Promise.allSettled([
					...sessionsToClose.map((session) => closeSession(session)),
					closeServer(server),
				]);
				const initializationResults = await Promise.allSettled([
					...initializationPromises,
				]);
				sessions.clear();
				pendingSessions.clear();
				const errors = [
					...cleanupErrors,
					...results.flatMap((result) =>
						result.status === "rejected" ? [result.reason] : [],
					),
					...initializationResults.flatMap((result) =>
						result.status === "rejected" ? [result.reason] : [],
					),
				];
				if (errors.length > 0) {
					throw aggregateErrors(errors, "HTTP server cleanup failed.");
				}
			})();
			return closePromise;
		},
	};
}
