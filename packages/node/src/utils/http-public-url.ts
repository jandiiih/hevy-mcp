/**
 * Public origin resolution for the Node HTTP transport.
 *
 * Behind a TLS-terminating proxy such as Railway, Fly.io, or a reverse proxy,
 * the socket the server accepts is plain HTTP on an internal port while the
 * URL clients actually use is `https://<public-host>`. OAuth metadata,
 * redirect URIs, and resource identifiers must all name the public origin, so
 * they are derived from the forwarded headers rather than the local bind
 * address.
 */

const PUBLIC_URL_ENV = "HEVY_MCP_PUBLIC_URL";

/**
 * The request headers this module reads. Kept structural so origin resolution
 * can be exercised without constructing a live HTTP request.
 */
export interface ForwardedRequest {
	readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

/** Only these schemes may come out of a forwarded header. */
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

function firstForwardedValue(value: string | string[] | undefined): string {
	// Proxies append to these headers, so a chain arrives as "https, http".
	// The left-most entry is the one the original client used.
	const raw = Array.isArray(value) ? value[0] : value;
	return (raw ?? "").split(",", 1)[0].trim();
}

/**
 * Parse a configured public URL into a bare origin. Returns undefined when the
 * value is missing or not a usable absolute http(s) URL, which lets callers
 * fall back to header-derived detection instead of failing startup.
 */
export function parsePublicOrigin(
	value: string | undefined,
): string | undefined {
	const trimmed = value?.trim();
	if (!trimmed) return undefined;
	try {
		const url = new URL(trimmed);
		if (!ALLOWED_PROTOCOLS.has(url.protocol)) return undefined;
		if (!url.hostname) return undefined;
		return url.origin;
	} catch {
		return undefined;
	}
}

export interface PublicOriginOptions {
	/** Explicitly configured origin; when present it always wins. */
	configuredOrigin?: string;
	/** Fallback scheme when no forwarded protocol header is present. */
	fallbackProtocol?: "http" | "https";
}

/**
 * Resolve the origin a client used to reach this request.
 *
 * `HEVY_MCP_PUBLIC_URL` takes precedence because it is the only source that
 * survives a misconfigured proxy. Otherwise the `Host` header names the
 * public host (proxies rewrite it) and `X-Forwarded-Proto` names the scheme.
 */
export function resolvePublicOrigin(
	request: ForwardedRequest,
	options: PublicOriginOptions = {},
): string | undefined {
	const configured = parsePublicOrigin(options.configuredOrigin);
	if (configured) return configured;

	const forwardedHost = firstForwardedValue(
		request.headers["x-forwarded-host"],
	);
	const hostHeader = Array.isArray(request.headers.host)
		? request.headers.host[0]
		: request.headers.host;
	const host = forwardedHost || (hostHeader ?? "").trim();
	if (!host) return undefined;

	const forwardedProto = firstForwardedValue(
		request.headers["x-forwarded-proto"],
	).toLowerCase();
	const protocol =
		forwardedProto === "https" || forwardedProto === "http"
			? forwardedProto
			: (options.fallbackProtocol ?? "http");

	try {
		const url = new URL(`${protocol}://${host}`);
		if (!url.hostname) return undefined;
		// A Host header carrying credentials, a path, or a query is malformed and
		// must never be reflected back into OAuth metadata.
		if (url.username || url.password || url.pathname !== "/" || url.search) {
			return undefined;
		}
		return url.origin;
	} catch {
		return undefined;
	}
}

/** Read the configured public origin from the process environment. */
export function configuredPublicOrigin(
	env: NodeJS.ProcessEnv = process.env,
): string | undefined {
	return parsePublicOrigin(env[PUBLIC_URL_ENV]);
}
