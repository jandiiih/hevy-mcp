import {
	createCipheriv,
	createDecipheriv,
	createHash,
	hkdfSync,
	randomBytes,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";

/**
 * Token, PKCE, and key-wrapping primitives for the Node OAuth 2.1 layer.
 *
 * The design goal is that the server's own storage is not enough to recover a
 * user's Hevy API key. Every issued credential (authorization code, access
 * token, refresh token) carries a high-entropy secret that is never stored;
 * only its SHA-256 digest is. The Hevy API key is sealed with a wrapping key
 * derived from that same secret, so the key can only be unsealed while a
 * client is presenting the matching credential. A stolen store file therefore
 * yields ciphertext and digests, not credentials.
 */

const SECRET_BYTES = 32;
const AES_KEY_BYTES = 32;
const AES_IV_BYTES = 12;
const HKDF_INFO = "hevy-mcp-oauth-key-wrap-v1";

/** Sealed Hevy API key. Meaningless without the credential secret. */
export interface WrappedApiKey {
	iv: string;
	ciphertext: string;
	tag: string;
}

/**
 * A credential in its three parts. Serialized as `userId:grantId:secret`,
 * which no Hevy API key can collide with because Hevy keys are UUIDs and
 * contain no colon. That lets the transport route a bearer value to either the
 * OAuth layer or the direct API-key path without ambiguity.
 */
export interface ParsedCredential {
	userId: string;
	grantId: string;
	secret: string;
}

export function randomSecret(): string {
	return randomBytes(SECRET_BYTES).toString("base64url");
}

export function randomId(): string {
	return randomUUID();
}

export function sha256(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Derive a stable, non-reversible user identity from the Hevy API key so that
 * re-authorizing with the same key reuses the same subject. Matches the
 * Worker's `deriveUserId`.
 */
export function deriveUserId(apiKey: string): string {
	return sha256(apiKey);
}

/** Constant-time digest comparison; never leaks a prefix match via timing. */
export function secretMatchesDigest(secret: string, digest: string): boolean {
	const actual = Buffer.from(sha256(secret), "hex");
	const expected = Buffer.from(digest, "hex");
	return (
		actual.byteLength === expected.byteLength &&
		actual.byteLength > 0 &&
		timingSafeEqual(actual, expected)
	);
}

export function formatCredential(credential: ParsedCredential): string {
	return `${credential.userId}:${credential.grantId}:${credential.secret}`;
}

export function parseCredential(value: string): ParsedCredential | null {
	const parts = value.split(":");
	if (parts.length !== 3) return null;
	const [userId, grantId, secret] = parts;
	if (!userId || !grantId || !secret) return null;
	return { userId, grantId, secret };
}

/**
 * Whether a bearer value has the OAuth credential shape. Used to decide
 * between the OAuth path and the direct Hevy-API-key path.
 */
export function hasCredentialFormat(value: string): boolean {
	return /^[^:\s]+:[^:\s]+:[^:\s]+$/u.test(value);
}

function wrappingKey(secret: string): Buffer {
	// HKDF binds the wrapping key to this specific purpose, so the same secret
	// used elsewhere (as a lookup digest) cannot double as a decryption key.
	return Buffer.from(
		hkdfSync(
			"sha256",
			Buffer.from(secret, "utf8"),
			"",
			HKDF_INFO,
			AES_KEY_BYTES,
		),
	);
}

export function wrapApiKey(apiKey: string, secret: string): WrappedApiKey {
	const iv = randomBytes(AES_IV_BYTES);
	const cipher = createCipheriv("aes-256-gcm", wrappingKey(secret), iv);
	const ciphertext = Buffer.concat([
		cipher.update(apiKey, "utf8"),
		cipher.final(),
	]);
	return {
		iv: iv.toString("base64"),
		ciphertext: ciphertext.toString("base64"),
		tag: cipher.getAuthTag().toString("base64"),
	};
}

/** Unseal a Hevy API key. Returns null on any tampering or wrong secret. */
export function unwrapApiKey(
	wrapped: WrappedApiKey,
	secret: string,
): string | null {
	try {
		const decipher = createDecipheriv(
			"aes-256-gcm",
			wrappingKey(secret),
			Buffer.from(wrapped.iv, "base64"),
		);
		decipher.setAuthTag(Buffer.from(wrapped.tag, "base64"));
		return Buffer.concat([
			decipher.update(Buffer.from(wrapped.ciphertext, "base64")),
			decipher.final(),
		]).toString("utf8");
	} catch {
		return null;
	}
}

/**
 * Verify an RFC 7636 S256 PKCE challenge. Only S256 is supported; `plain`
 * offers no protection against an intercepted authorization code and the MCP
 * authorization spec requires S256.
 */
export function verifyPkceS256(
	codeVerifier: string,
	codeChallenge: string,
): boolean {
	const computed = createHash("sha256")
		.update(codeVerifier, "utf8")
		.digest("base64url");
	const actual = Buffer.from(computed, "utf8");
	const expected = Buffer.from(codeChallenge, "utf8");
	return (
		actual.byteLength === expected.byteLength &&
		actual.byteLength > 0 &&
		timingSafeEqual(actual, expected)
	);
}
