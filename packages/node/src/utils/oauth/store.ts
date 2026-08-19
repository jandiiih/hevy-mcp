import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";

/**
 * Storage for OAuth clients, authorization codes, and grants.
 *
 * The default backing store is process memory, which is the honest match for a
 * single-instance deployment: a restart invalidates outstanding grants and
 * clients re-authorize. Setting `HEVY_MCP_OAUTH_STORE_PATH` (a mounted volume
 * on a hosted platform) persists the same records across restarts so a
 * redeploy does not disconnect the connector.
 *
 * Nothing written here can be used on its own: API keys are sealed against
 * credential secrets that exist only in the client's possession, and secrets
 * are stored as digests.
 */

const wrappedApiKeySchema = z.object({
	iv: z.string(),
	ciphertext: z.string(),
	tag: z.string(),
});

const credentialRecordSchema = z.object({
	secretDigest: z.string(),
	expiresAt: z.number(),
	wrappedApiKey: wrappedApiKeySchema,
});

const clientRecordSchema = z.object({
	clientId: z.string(),
	clientName: z.string(),
	redirectUris: z.array(z.string()),
	clientSecretDigest: z.string().optional(),
	createdAt: z.number(),
});

const authorizationCodeRecordSchema = z.object({
	grantId: z.string(),
	userId: z.string(),
	clientId: z.string(),
	redirectUri: z.string(),
	codeChallenge: z.string(),
	scope: z.array(z.string()),
	resource: z.string().optional(),
	credential: credentialRecordSchema,
});

const grantRecordSchema = z.object({
	grantId: z.string(),
	userId: z.string(),
	clientId: z.string(),
	scope: z.array(z.string()),
	createdAt: z.number(),
	accessToken: credentialRecordSchema.optional(),
	refreshToken: credentialRecordSchema.optional(),
});

const persistedStateSchema = z.object({
	version: z.literal(1),
	clients: z.array(clientRecordSchema),
	grants: z.array(grantRecordSchema),
});

export type CredentialRecord = z.infer<typeof credentialRecordSchema>;
export type ClientRecord = z.infer<typeof clientRecordSchema>;
export type AuthorizationCodeRecord = z.infer<
	typeof authorizationCodeRecordSchema
>;
export type GrantRecord = z.infer<typeof grantRecordSchema>;

export interface OAuthStoreOptions {
	/** Absolute path for persistence. Omit to keep everything in memory. */
	persistencePath?: string;
	now?: () => number;
}

export class OAuthStore {
	readonly #clients = new Map<string, ClientRecord>();
	readonly #codes = new Map<string, AuthorizationCodeRecord>();
	readonly #grants = new Map<string, GrantRecord>();
	readonly #persistencePath: string | undefined;
	readonly #now: () => number;

	constructor(options: OAuthStoreOptions = {}) {
		this.#persistencePath = options.persistencePath;
		this.#now = options.now ?? (() => Date.now());
		this.#load();
	}

	/** Whether records survive a process restart. */
	get persistent(): boolean {
		return this.#persistencePath !== undefined;
	}

	registerClient(client: ClientRecord): void {
		this.#clients.set(client.clientId, client);
		this.#persist();
	}

	getClient(clientId: string): ClientRecord | undefined {
		return this.#clients.get(clientId);
	}

	get clientCount(): number {
		return this.#clients.size;
	}

	/**
	 * Drop the oldest registered client that holds no grant, so an unbounded
	 * stream of dynamic registrations cannot grow the store without limit while
	 * a client the user actually connected stays untouched.
	 */
	evictOldestUnusedClient(): boolean {
		const inUse = new Set(
			Array.from(this.#grants.values(), (grant) => grant.clientId),
		);
		let oldest: ClientRecord | undefined;
		for (const client of this.#clients.values()) {
			if (inUse.has(client.clientId)) continue;
			if (!oldest || client.createdAt < oldest.createdAt) oldest = client;
		}
		if (!oldest) return false;
		this.#clients.delete(oldest.clientId);
		this.#persist();
		return true;
	}

	/**
	 * Authorization codes are single-use and short-lived, so they stay in
	 * memory even when persistence is on: losing them on restart only costs an
	 * in-flight authorization that the client will simply retry.
	 */
	putAuthorizationCode(grantId: string, record: AuthorizationCodeRecord): void {
		this.#codes.set(grantId, record);
	}

	/** Consume a code. Codes are removed on first read, valid or not. */
	takeAuthorizationCode(grantId: string): AuthorizationCodeRecord | undefined {
		const record = this.#codes.get(grantId);
		this.#codes.delete(grantId);
		if (!record) return undefined;
		return record.credential.expiresAt <= this.#now() ? undefined : record;
	}

	putGrant(grant: GrantRecord): void {
		this.#grants.set(grant.grantId, grant);
		this.#persist();
	}

	getGrant(grantId: string): GrantRecord | undefined {
		return this.#grants.get(grantId);
	}

	deleteGrant(grantId: string): void {
		if (this.#grants.delete(grantId)) this.#persist();
	}

	/**
	 * Drop expired codes and grants. A grant is dead once its refresh token has
	 * expired, because no new access token can ever be minted from it.
	 */
	sweep(): void {
		const now = this.#now();
		let changed = false;
		for (const [grantId, record] of this.#codes) {
			if (record.credential.expiresAt <= now) this.#codes.delete(grantId);
		}
		for (const [grantId, grant] of this.#grants) {
			const refreshExpiry = grant.refreshToken?.expiresAt ?? 0;
			const accessExpiry = grant.accessToken?.expiresAt ?? 0;
			if (Math.max(refreshExpiry, accessExpiry) <= now) {
				this.#grants.delete(grantId);
				changed = true;
			}
		}
		if (changed) this.#persist();
	}

	#load(): void {
		if (!this.#persistencePath) return;
		let raw: string;
		try {
			raw = readFileSync(this.#persistencePath, "utf8");
		} catch {
			// A missing file is the normal first-boot case.
			return;
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(raw);
		} catch {
			console.error(
				"OAuth store file is not valid JSON; starting with an empty store.",
			);
			return;
		}
		const result = persistedStateSchema.safeParse(parsed);
		if (!result.success) {
			console.error(
				"OAuth store file has an unexpected shape; starting with an empty store.",
			);
			return;
		}
		for (const client of result.data.clients) {
			this.#clients.set(client.clientId, client);
		}
		for (const grant of result.data.grants) {
			this.#grants.set(grant.grantId, grant);
		}
	}

	#persist(): void {
		const path = this.#persistencePath;
		if (!path) return;
		const state = {
			version: 1 as const,
			clients: [...this.#clients.values()],
			grants: [...this.#grants.values()],
		};
		try {
			mkdirSync(dirname(path), { recursive: true });
			// Write-then-rename so a crash mid-write cannot truncate the store.
			const temporaryPath = `${path}.tmp`;
			writeFileSync(temporaryPath, JSON.stringify(state), { mode: 0o600 });
			renameSync(temporaryPath, path);
		} catch (error) {
			// Persistence is a convenience; losing it must not break authorization.
			console.error(
				`OAuth store could not be persisted: ${
					error instanceof Error ? error.name : "unknown error"
				}`,
			);
		}
	}
}
