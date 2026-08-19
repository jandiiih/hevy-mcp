import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import {
	AUTHORIZATION_SERVER_METADATA_PATH,
	AUTHORIZE_PATH,
	OAUTH_SCOPES,
	OPENID_CONFIGURATION_PATH,
	PROTECTED_RESOURCE_METADATA_PATH,
	REGISTER_PATH,
	TOKEN_PATH,
	authorizationServerMetadata,
	protectedResourceMetadata,
} from "./metadata.js";
import {
	HTML_RESPONSE_HEADERS,
	renderAuthorizeError,
	renderAuthorizePage,
} from "./authorize-page.js";
import { OAuthStore, type ClientRecord } from "./store.js";
import {
	deriveUserId,
	formatCredential,
	parseCredential,
	randomId,
	randomSecret,
	secretMatchesDigest,
	sha256,
	unwrapApiKey,
	verifyPkceS256,
	wrapApiKey,
} from "./tokens.js";

/**
 * OAuth 2.1 authorization server for the Node HTTP transport.
 *
 * This mirrors the Cloudflare Worker's OAuth layer, which is built on
 * `@cloudflare/workers-oauth-provider` and therefore cannot run on Node. The
 * flow is the one remote MCP clients expect: RFC 7591 dynamic client
 * registration, authorization code with mandatory S256 PKCE, and refresh
 * tokens. The user proves ownership of a Hevy account by pasting their API
 * key on the consent page; that key becomes the credential the MCP session
 * uses upstream.
 */

/** Long-lived by OAuth standards, matching the Worker. Clients auto-refresh. */
export const ACCESS_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
/** Codes are redeemed within seconds; a short window limits replay exposure. */
const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;

const MAX_REGISTERED_CLIENTS = 200;
const MAX_BODY_BYTES = 64 * 1024;
const BODY_TIMEOUT_MS = 10_000;

export type ApiKeyValidation = "valid" | "invalid" | "unavailable";

export interface OAuthProviderOptions {
	store: OAuthStore;
	/**
	 * Checks a Hevy API key against the Hevy API. Declared as a callback
	 * property rather than a method so it carries no `this` binding.
	 */
	validateApiKey: (
		apiKey: string,
		signal?: AbortSignal,
	) => Promise<ApiKeyValidation>;
	/** Path the MCP endpoint is served on; named as the protected resource. */
	resourcePath: string;
	now?: () => number;
}

export interface AuthenticatedGrant {
	apiKey: string;
	userId: string;
	grantId: string;
}

export type BearerAuthentication =
	| { kind: "authenticated"; grant: AuthenticatedGrant }
	| { kind: "rejected"; reason: string };

/** Registration metadata accepted from a dynamic client registration request. */
const registrationRequestSchema = z.object({
	redirect_uris: z.array(z.string()).min(1),
	client_name: z.string().optional(),
	token_endpoint_auth_method: z.string().optional(),
	grant_types: z.array(z.string()).optional(),
	response_types: z.array(z.string()).optional(),
});

const authorizationRequestSchema = z.object({
	clientId: z.string().min(1),
	redirectUri: z.string().min(1),
	scope: z.array(z.string()),
	state: z.string(),
	codeChallenge: z.string().min(1),
	resource: z.string().optional(),
});

type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>;

/** Any value this module serializes into a JSON response body. */
type JsonValue =
	| string
	| number
	| boolean
	| null
	| undefined
	| JsonValue[]
	| { [key: string]: JsonValue };

function writeJson(
	response: ServerResponse,
	status: number,
	body: JsonValue,
	headers: Readonly<Record<string, string>> = {},
): void {
	if (response.headersSent || response.destroyed) return;
	response.statusCode = status;
	response.setHeader("Content-Type", "application/json");
	response.setHeader("Cache-Control", "no-store");
	for (const [name, value] of Object.entries(headers)) {
		response.setHeader(name, value);
	}
	response.end(JSON.stringify(body));
}

function writeHtml(
	response: ServerResponse,
	status: number,
	body: string,
): void {
	if (response.headersSent || response.destroyed) return;
	response.statusCode = status;
	for (const [name, value] of Object.entries(HTML_RESPONSE_HEADERS)) {
		response.setHeader(name, value);
	}
	response.end(body);
}

function oauthError(
	response: ServerResponse,
	status: number,
	error: string,
	description: string,
): void {
	writeJson(response, status, {
		error,
		error_description: description,
	});
}

/** Read a bounded request body as text. Oversized or slow bodies are refused. */
function readTextBody(request: IncomingMessage): Promise<string | null> {
	return new Promise((resolve) => {
		const chunks: Buffer[] = [];
		let size = 0;
		let settled = false;
		const finish = (value: string | null) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			request.removeAllListeners("data");
			request.removeAllListeners("end");
			request.removeAllListeners("error");
			resolve(value);
		};
		const timer = setTimeout(() => {
			request.resume();
			finish(null);
		}, BODY_TIMEOUT_MS);
		timer.unref?.();
		request.on("data", (chunk: Buffer | string) => {
			const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			size += buffer.byteLength;
			if (size > MAX_BODY_BYTES) {
				request.resume();
				finish(null);
				return;
			}
			chunks.push(buffer);
		});
		request.once("end", () => finish(Buffer.concat(chunks).toString("utf8")));
		request.once("error", () => finish(null));
	});
}

function encodeAuthorizationRequest(value: AuthorizationRequest): string {
	return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeAuthorizationRequest(
	encoded: string,
): AuthorizationRequest | null {
	try {
		const parsed: unknown = JSON.parse(
			Buffer.from(encoded, "base64url").toString("utf8"),
		);
		const result = authorizationRequestSchema.safeParse(parsed);
		return result.success ? result.data : null;
	} catch {
		return null;
	}
}

/**
 * A redirect URI is accepted only when it exactly matches one the client
 * registered. Prefix or host-only matching is what turns an OAuth server into
 * an open redirector that leaks authorization codes.
 */
function isRegisteredRedirectUri(
	client: ClientRecord,
	redirectUri: string,
): boolean {
	return client.redirectUris.includes(redirectUri);
}

function redirectWithError(
	response: ServerResponse,
	redirectUri: string,
	state: string,
	error: string,
	description: string,
): void {
	const target = new URL(redirectUri);
	target.searchParams.set("error", error);
	target.searchParams.set("error_description", description);
	if (state) target.searchParams.set("state", state);
	response.statusCode = 302;
	response.setHeader("Location", target.toString());
	response.setHeader("Cache-Control", "no-store");
	response.end();
}

export class HevyOAuthProvider {
	readonly #store: OAuthStore;
	readonly #validateApiKey: OAuthProviderOptions["validateApiKey"];
	readonly #resourcePath: string;
	readonly #now: () => number;

	constructor(options: OAuthProviderOptions) {
		this.#store = options.store;
		this.#validateApiKey = options.validateApiKey;
		this.#resourcePath = options.resourcePath;
		this.#now = options.now ?? (() => Date.now());
	}

	/** Whether this path belongs to the OAuth layer rather than the MCP endpoint. */
	handlesPath(pathname: string): boolean {
		return (
			pathname === AUTHORIZE_PATH ||
			pathname === TOKEN_PATH ||
			pathname === REGISTER_PATH ||
			pathname === OPENID_CONFIGURATION_PATH ||
			pathname === AUTHORIZATION_SERVER_METADATA_PATH ||
			pathname.startsWith(`${AUTHORIZATION_SERVER_METADATA_PATH}/`) ||
			pathname === PROTECTED_RESOURCE_METADATA_PATH ||
			pathname.startsWith(`${PROTECTED_RESOURCE_METADATA_PATH}/`)
		);
	}

	/**
	 * The `WWW-Authenticate` value that starts the authorization flow. Pointing
	 * at the resource metadata is what lets a client discover the authorization
	 * server without any manual configuration.
	 */
	unauthorizedHeader(origin: string, description: string): string {
		const metadataUrl = `${origin}${PROTECTED_RESOURCE_METADATA_PATH}${this.#resourcePath}`;
		return (
			`Bearer error="invalid_token", error_description="${description}", ` +
			`resource_metadata="${metadataUrl}"`
		);
	}

	/** Exchange a bearer access token for the Hevy API key it stands for. */
	authenticateBearer(token: string): BearerAuthentication {
		const credential = parseCredential(token);
		if (!credential) {
			return { kind: "rejected", reason: "Malformed access token" };
		}
		const grant = this.#store.getGrant(credential.grantId);
		if (!grant || grant.userId !== credential.userId) {
			return { kind: "rejected", reason: "Unknown access token" };
		}
		const accessToken = grant.accessToken;
		if (!accessToken) {
			return { kind: "rejected", reason: "Unknown access token" };
		}
		if (accessToken.expiresAt <= this.#now()) {
			return { kind: "rejected", reason: "Access token expired" };
		}
		if (!secretMatchesDigest(credential.secret, accessToken.secretDigest)) {
			return { kind: "rejected", reason: "Unknown access token" };
		}
		const apiKey = unwrapApiKey(accessToken.wrappedApiKey, credential.secret);
		if (!apiKey) {
			return { kind: "rejected", reason: "Grant could not be unsealed" };
		}
		return {
			kind: "authenticated",
			grant: { apiKey, userId: grant.userId, grantId: grant.grantId },
		};
	}

	async handleRequest(
		request: IncomingMessage,
		response: ServerResponse,
		pathname: string,
		origin: string,
	): Promise<void> {
		if (
			pathname === PROTECTED_RESOURCE_METADATA_PATH ||
			pathname.startsWith(`${PROTECTED_RESOURCE_METADATA_PATH}/`)
		) {
			this.#requireGet(request, response, () =>
				writeJson(
					response,
					200,
					protectedResourceMetadata(origin, this.#resourcePath),
				),
			);
			return;
		}
		if (
			pathname === AUTHORIZATION_SERVER_METADATA_PATH ||
			pathname.startsWith(`${AUTHORIZATION_SERVER_METADATA_PATH}/`) ||
			pathname === OPENID_CONFIGURATION_PATH
		) {
			this.#requireGet(request, response, () =>
				writeJson(response, 200, authorizationServerMetadata(origin)),
			);
			return;
		}
		if (pathname === REGISTER_PATH) {
			await this.#handleRegister(request, response);
			return;
		}
		if (pathname === AUTHORIZE_PATH) {
			await this.#handleAuthorize(request, response, origin);
			return;
		}
		if (pathname === TOKEN_PATH) {
			await this.#handleToken(request, response);
			return;
		}
		writeJson(response, 404, { error: "not_found" });
	}

	#requireGet(
		request: IncomingMessage,
		response: ServerResponse,
		handler: () => void,
	): void {
		if (request.method !== "GET" && request.method !== "HEAD") {
			writeJson(
				response,
				405,
				{ error: "method_not_allowed" },
				{
					Allow: "GET",
				},
			);
			return;
		}
		handler();
	}

	async #handleRegister(
		request: IncomingMessage,
		response: ServerResponse,
	): Promise<void> {
		if (request.method !== "POST") {
			oauthError(
				response,
				405,
				"invalid_request",
				"Client registration requires POST.",
			);
			return;
		}
		const body = await readTextBody(request);
		if (body === null) {
			oauthError(
				response,
				400,
				"invalid_client_metadata",
				"Registration body could not be read.",
			);
			return;
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(body);
		} catch {
			oauthError(
				response,
				400,
				"invalid_client_metadata",
				"Registration body must be valid JSON.",
			);
			return;
		}
		const result = registrationRequestSchema.safeParse(parsed);
		if (!result.success) {
			oauthError(
				response,
				400,
				"invalid_client_metadata",
				"redirect_uris is required and must be a non-empty array.",
			);
			return;
		}
		const redirectUris = result.data.redirect_uris.filter((uri) => {
			try {
				const url = new URL(uri);
				// A code delivered over plain HTTP to a remote host is interceptable.
				// Loopback stays allowed so local clients can complete the flow.
				return (
					url.protocol === "https:" ||
					url.hostname === "localhost" ||
					url.hostname === "127.0.0.1" ||
					url.hostname === "[::1]" ||
					url.hostname === "::1"
				);
			} catch {
				return false;
			}
		});
		if (redirectUris.length === 0) {
			oauthError(
				response,
				400,
				"invalid_redirect_uri",
				"redirect_uris must contain an https URL or a loopback URL.",
			);
			return;
		}

		if (this.#store.clientCount >= MAX_REGISTERED_CLIENTS) {
			this.#store.evictOldestUnusedClient();
		}
		if (this.#store.clientCount >= MAX_REGISTERED_CLIENTS) {
			oauthError(
				response,
				429,
				"temporarily_unavailable",
				"Client registration limit reached.",
			);
			return;
		}

		const clientId = randomId();
		const createdAt = this.#now();
		// Claude and other MCP clients register as public clients and rely on
		// PKCE, so a secret is issued only when the client explicitly asks.
		const wantsSecret =
			result.data.token_endpoint_auth_method !== undefined &&
			result.data.token_endpoint_auth_method !== "none";
		const clientSecret = wantsSecret ? randomSecret() : undefined;
		this.#store.registerClient({
			clientId,
			clientName: result.data.client_name?.trim() || clientId,
			redirectUris,
			clientSecretDigest: clientSecret ? sha256(clientSecret) : undefined,
			createdAt,
		});
		writeJson(response, 201, {
			client_id: clientId,
			client_id_issued_at: Math.floor(createdAt / 1000),
			redirect_uris: redirectUris,
			client_name: result.data.client_name,
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			token_endpoint_auth_method: wantsSecret ? "client_secret_post" : "none",
			scope: OAUTH_SCOPES.join(" "),
			// Omitted for public clients, which authenticate with PKCE alone.
			client_secret: clientSecret,
		});
	}

	async #handleAuthorize(
		request: IncomingMessage,
		response: ServerResponse,
		origin: string,
	): Promise<void> {
		if (request.method === "GET") {
			this.#handleAuthorizeGet(request, response, origin);
			return;
		}
		if (request.method === "POST") {
			await this.#handleAuthorizePost(request, response);
			return;
		}
		writeJson(
			response,
			405,
			{ error: "method_not_allowed" },
			{
				Allow: "GET, POST",
			},
		);
	}

	#handleAuthorizeGet(
		request: IncomingMessage,
		response: ServerResponse,
		origin: string,
	): void {
		const url = new URL(request.url ?? "/", origin);
		const query = url.searchParams;
		const clientId = query.get("client_id") ?? "";
		const redirectUri = query.get("redirect_uri") ?? "";
		const state = query.get("state") ?? "";

		const client = clientId ? this.#store.getClient(clientId) : undefined;
		if (!client) {
			writeHtml(response, 400, renderAuthorizeError("Unknown OAuth client."));
			return;
		}
		if (!redirectUri || !isRegisteredRedirectUri(client, redirectUri)) {
			// Never redirect to an unverified URI: report in-place instead.
			writeHtml(
				response,
				400,
				renderAuthorizeError(
					"redirect_uri does not match a registered redirect URI.",
				),
			);
			return;
		}
		if (query.get("response_type") !== "code") {
			redirectWithError(
				response,
				redirectUri,
				state,
				"unsupported_response_type",
				"Only the authorization code flow is supported.",
			);
			return;
		}
		const codeChallenge = query.get("code_challenge") ?? "";
		if (!codeChallenge || query.get("code_challenge_method") !== "S256") {
			redirectWithError(
				response,
				redirectUri,
				state,
				"invalid_request",
				"PKCE with a S256 code_challenge is required.",
			);
			return;
		}

		const scope = (query.get("scope") ?? OAUTH_SCOPES.join(" "))
			.split(/\s+/u)
			.filter(Boolean);
		const authorizationRequest: AuthorizationRequest = {
			clientId,
			redirectUri,
			scope: scope.length > 0 ? scope : [...OAUTH_SCOPES],
			state,
			codeChallenge,
			resource: query.get("resource") ?? undefined,
		};
		writeHtml(
			response,
			200,
			renderAuthorizePage({
				clientName: client.clientName,
				encodedRequest: encodeAuthorizationRequest(authorizationRequest),
			}),
		);
	}

	async #handleAuthorizePost(
		request: IncomingMessage,
		response: ServerResponse,
	): Promise<void> {
		const body = await readTextBody(request);
		if (body === null) {
			writeHtml(
				response,
				400,
				renderAuthorizeError("Invalid form submission."),
			);
			return;
		}
		const form = new URLSearchParams(body);
		const encodedRequest = form.get("oauth_request") ?? "";
		const authorizationRequest = decodeAuthorizationRequest(encodedRequest);
		if (!authorizationRequest) {
			writeHtml(
				response,
				400,
				renderAuthorizeError("Invalid authorization request."),
			);
			return;
		}
		const client = this.#store.getClient(authorizationRequest.clientId);
		if (
			!client ||
			!isRegisteredRedirectUri(client, authorizationRequest.redirectUri)
		) {
			writeHtml(response, 400, renderAuthorizeError("Unknown OAuth client."));
			return;
		}
		const rerender = (message: string, status: number): void =>
			writeHtml(
				response,
				status,
				renderAuthorizePage({
					clientName: client.clientName,
					encodedRequest,
					error: message,
				}),
			);

		const apiKey = (form.get("hevy_api_key") ?? "").trim();
		if (!apiKey) {
			rerender("Enter your Hevy API key.", 400);
			return;
		}

		let validation: ApiKeyValidation;
		try {
			validation = await this.#validateApiKey(apiKey);
		} catch {
			rerender("Unable to validate the Hevy API key. Try again.", 502);
			return;
		}
		if (validation === "unavailable") {
			rerender("Unable to reach Hevy right now. Try again.", 502);
			return;
		}
		if (validation === "invalid") {
			rerender("Hevy rejected this API key. Check the key and try again.", 401);
			return;
		}

		const userId = deriveUserId(apiKey);
		const grantId = randomId();
		const codeSecret = randomSecret();
		this.#store.putAuthorizationCode(grantId, {
			grantId,
			userId,
			clientId: client.clientId,
			redirectUri: authorizationRequest.redirectUri,
			codeChallenge: authorizationRequest.codeChallenge,
			scope: authorizationRequest.scope,
			resource: authorizationRequest.resource,
			credential: {
				secretDigest: sha256(codeSecret),
				expiresAt: this.#now() + AUTHORIZATION_CODE_TTL_MS,
				wrappedApiKey: wrapApiKey(apiKey, codeSecret),
			},
		});

		const target = new URL(authorizationRequest.redirectUri);
		target.searchParams.set(
			"code",
			formatCredential({ userId, grantId, secret: codeSecret }),
		);
		if (authorizationRequest.state) {
			target.searchParams.set("state", authorizationRequest.state);
		}
		response.statusCode = 302;
		response.setHeader("Location", target.toString());
		response.setHeader("Cache-Control", "no-store");
		response.end();
	}

	async #handleToken(
		request: IncomingMessage,
		response: ServerResponse,
	): Promise<void> {
		if (request.method !== "POST") {
			oauthError(
				response,
				405,
				"invalid_request",
				"The token endpoint requires POST.",
			);
			return;
		}
		const body = await readTextBody(request);
		if (body === null) {
			oauthError(
				response,
				400,
				"invalid_request",
				"Token request body could not be read.",
			);
			return;
		}
		const form = new URLSearchParams(body);
		const grantType = form.get("grant_type");
		if (grantType === "authorization_code") {
			this.#handleAuthorizationCodeGrant(form, response);
			return;
		}
		if (grantType === "refresh_token") {
			this.#handleRefreshTokenGrant(form, response);
			return;
		}
		oauthError(
			response,
			400,
			"unsupported_grant_type",
			"Supported grants are authorization_code and refresh_token.",
		);
	}

	#authenticateClient(
		form: URLSearchParams,
		clientId: string,
	): ClientRecord | null {
		const client = this.#store.getClient(clientId);
		if (!client) return null;
		if (!client.clientSecretDigest) return client;
		const presented = form.get("client_secret") ?? "";
		return secretMatchesDigest(presented, client.clientSecretDigest)
			? client
			: null;
	}

	#handleAuthorizationCodeGrant(
		form: URLSearchParams,
		response: ServerResponse,
	): void {
		const code = form.get("code") ?? "";
		const codeVerifier = form.get("code_verifier") ?? "";
		const credential = parseCredential(code);
		if (!credential || !codeVerifier) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"Authorization code and code_verifier are required.",
			);
			return;
		}
		// Read-and-delete: a code replayed after this point finds nothing.
		const record = this.#store.takeAuthorizationCode(credential.grantId);
		if (
			!record ||
			record.userId !== credential.userId ||
			!secretMatchesDigest(credential.secret, record.credential.secretDigest)
		) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"Authorization code is invalid or expired.",
			);
			return;
		}
		const clientId = form.get("client_id") ?? record.clientId;
		if (clientId !== record.clientId) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"Authorization code was issued to a different client.",
			);
			return;
		}
		if (!this.#authenticateClient(form, clientId)) {
			oauthError(
				response,
				401,
				"invalid_client",
				"Client authentication failed.",
			);
			return;
		}
		const redirectUri = form.get("redirect_uri");
		if (redirectUri !== null && redirectUri !== record.redirectUri) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"redirect_uri does not match the authorization request.",
			);
			return;
		}
		if (!verifyPkceS256(codeVerifier, record.codeChallenge)) {
			oauthError(response, 400, "invalid_grant", "PKCE verification failed.");
			return;
		}
		const apiKey = unwrapApiKey(
			record.credential.wrappedApiKey,
			credential.secret,
		);
		if (!apiKey) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"Authorization code could not be unsealed.",
			);
			return;
		}
		this.#issueTokens(response, {
			grantId: record.grantId,
			userId: record.userId,
			clientId: record.clientId,
			scope: record.scope,
			createdAt: this.#now(),
			apiKey,
		});
	}

	#handleRefreshTokenGrant(
		form: URLSearchParams,
		response: ServerResponse,
	): void {
		const presented = form.get("refresh_token") ?? "";
		const credential = parseCredential(presented);
		if (!credential) {
			oauthError(response, 400, "invalid_grant", "Refresh token is invalid.");
			return;
		}
		const grant = this.#store.getGrant(credential.grantId);
		const refreshToken = grant?.refreshToken;
		if (
			!grant ||
			!refreshToken ||
			grant.userId !== credential.userId ||
			refreshToken.expiresAt <= this.#now() ||
			!secretMatchesDigest(credential.secret, refreshToken.secretDigest)
		) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"Refresh token is invalid or expired.",
			);
			return;
		}
		const clientId = form.get("client_id") ?? grant.clientId;
		if (clientId !== grant.clientId) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"Refresh token was issued to a different client.",
			);
			return;
		}
		if (!this.#authenticateClient(form, clientId)) {
			oauthError(
				response,
				401,
				"invalid_client",
				"Client authentication failed.",
			);
			return;
		}
		const apiKey = unwrapApiKey(refreshToken.wrappedApiKey, credential.secret);
		if (!apiKey) {
			oauthError(
				response,
				400,
				"invalid_grant",
				"Refresh token could not be unsealed.",
			);
			return;
		}
		this.#issueTokens(response, {
			grantId: grant.grantId,
			userId: grant.userId,
			clientId: grant.clientId,
			scope: grant.scope,
			createdAt: grant.createdAt,
			apiKey,
		});
	}

	/**
	 * Mint a fresh access/refresh pair and reseal the Hevy API key under each
	 * new secret. Refresh tokens rotate on every use, so a leaked refresh token
	 * stops working as soon as the legitimate client refreshes.
	 */
	#issueTokens(
		response: ServerResponse,
		params: {
			grantId: string;
			userId: string;
			clientId: string;
			scope: string[];
			createdAt: number;
			apiKey: string;
		},
	): void {
		const now = this.#now();
		const accessSecret = randomSecret();
		const refreshSecret = randomSecret();
		this.#store.putGrant({
			grantId: params.grantId,
			userId: params.userId,
			clientId: params.clientId,
			scope: params.scope,
			createdAt: params.createdAt,
			accessToken: {
				secretDigest: sha256(accessSecret),
				expiresAt: now + ACCESS_TOKEN_TTL_SECONDS * 1000,
				wrappedApiKey: wrapApiKey(params.apiKey, accessSecret),
			},
			refreshToken: {
				secretDigest: sha256(refreshSecret),
				expiresAt: now + REFRESH_TOKEN_TTL_SECONDS * 1000,
				wrappedApiKey: wrapApiKey(params.apiKey, refreshSecret),
			},
		});
		const identity = { userId: params.userId, grantId: params.grantId };
		writeJson(response, 200, {
			access_token: formatCredential({ ...identity, secret: accessSecret }),
			token_type: "Bearer",
			expires_in: ACCESS_TOKEN_TTL_SECONDS,
			refresh_token: formatCredential({ ...identity, secret: refreshSecret }),
			scope: params.scope.join(" "),
		});
	}
}
