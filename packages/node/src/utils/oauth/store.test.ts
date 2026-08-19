import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OAuthStore, type GrantRecord } from "./store.js";
import { randomSecret, sha256, wrapApiKey } from "./tokens.js";

function temporaryStorePath(): string {
	return join(mkdtempSync(join(tmpdir(), "hevy-oauth-")), "store.json");
}

function credential(expiresAt: number) {
	const secret = randomSecret();
	return {
		secretDigest: sha256(secret),
		expiresAt,
		wrappedApiKey: wrapApiKey("hevy-key", secret),
	};
}

function grant(overrides: Partial<GrantRecord> = {}): GrantRecord {
	return {
		grantId: "grant-1",
		userId: "user-1",
		clientId: "client-1",
		scope: ["mcp"],
		createdAt: 1000,
		accessToken: credential(Number.MAX_SAFE_INTEGER),
		refreshToken: credential(Number.MAX_SAFE_INTEGER),
		...overrides,
	};
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("OAuthStore", () => {
	it("keeps records in memory when no path is configured", () => {
		const store = new OAuthStore();
		expect(store.persistent).toBe(false);
		store.putGrant(grant());
		expect(store.getGrant("grant-1")?.userId).toBe("user-1");
	});

	it("consumes an authorization code exactly once", () => {
		const store = new OAuthStore();
		store.putAuthorizationCode("grant-1", {
			grantId: "grant-1",
			userId: "user-1",
			clientId: "client-1",
			redirectUri: "https://claude.ai/cb",
			codeChallenge: "challenge",
			scope: ["mcp"],
			credential: credential(Number.MAX_SAFE_INTEGER),
		});
		expect(store.takeAuthorizationCode("grant-1")).toBeDefined();
		expect(store.takeAuthorizationCode("grant-1")).toBeUndefined();
	});

	it("treats an expired authorization code as absent", () => {
		const store = new OAuthStore({ now: () => 5000 });
		store.putAuthorizationCode("grant-1", {
			grantId: "grant-1",
			userId: "user-1",
			clientId: "client-1",
			redirectUri: "https://claude.ai/cb",
			codeChallenge: "challenge",
			scope: ["mcp"],
			credential: credential(1000),
		});
		expect(store.takeAuthorizationCode("grant-1")).toBeUndefined();
	});

	it("sweeps grants whose tokens have all expired", () => {
		const store = new OAuthStore({ now: () => 10_000 });
		store.putGrant(
			grant({
				grantId: "dead",
				accessToken: credential(1000),
				refreshToken: credential(2000),
			}),
		);
		store.putGrant(grant({ grantId: "alive" }));
		store.sweep();
		expect(store.getGrant("dead")).toBeUndefined();
		expect(store.getGrant("alive")).toBeDefined();
	});

	it("restores clients and grants from a persisted file", () => {
		const path = temporaryStorePath();
		const first = new OAuthStore({ persistencePath: path });
		expect(first.persistent).toBe(true);
		first.registerClient({
			clientId: "client-1",
			clientName: "Claude",
			redirectUris: ["https://claude.ai/cb"],
			createdAt: 1000,
		});
		first.putGrant(grant());

		const second = new OAuthStore({ persistencePath: path });
		expect(second.getClient("client-1")?.clientName).toBe("Claude");
		expect(second.getGrant("grant-1")?.userId).toBe("user-1");
	});

	it("never writes a Hevy API key in the clear", () => {
		const path = temporaryStorePath();
		const store = new OAuthStore({ persistencePath: path });
		store.putGrant(grant());
		expect(readFileSync(path, "utf8")).not.toContain("hevy-key");
	});

	it("starts empty rather than throwing on a corrupt store file", () => {
		const path = temporaryStorePath();
		writeFileSync(path, "{ not json");
		vi.spyOn(console, "error").mockImplementation(() => {});
		const store = new OAuthStore({ persistencePath: path });
		expect(store.getGrant("grant-1")).toBeUndefined();
		expect(console.error).toHaveBeenCalled();
	});

	it("starts empty when the persisted shape is unrecognized", () => {
		const path = temporaryStorePath();
		writeFileSync(path, JSON.stringify({ version: 99, clients: "nope" }));
		vi.spyOn(console, "error").mockImplementation(() => {});
		const store = new OAuthStore({ persistencePath: path });
		expect(store.clientCount).toBe(0);
	});

	it("evicts only a registered client that holds no grant", () => {
		const store = new OAuthStore();
		store.registerClient({
			clientId: "used",
			clientName: "used",
			redirectUris: ["https://claude.ai/cb"],
			createdAt: 1,
		});
		store.registerClient({
			clientId: "unused",
			clientName: "unused",
			redirectUris: ["https://claude.ai/cb"],
			createdAt: 2,
		});
		store.putGrant(grant({ clientId: "used" }));

		expect(store.evictOldestUnusedClient()).toBe(true);
		expect(store.getClient("unused")).toBeUndefined();
		expect(store.getClient("used")).toBeDefined();
		// Nothing left to evict once every client is in use.
		expect(store.evictOldestUnusedClient()).toBe(false);
	});

	it("reports whether the configured path is actually writable", () => {
		const path = temporaryStorePath();
		const working = new OAuthStore({ persistencePath: path });
		expect(working.persistent).toBe(true);
		expect(working.persistenceWritable).toBe(true);

		// An unwritable path is the shape of a volume mounted for another user.
		// It must be reported, not silently degraded to memory-only.
		const blocker = join(mkdtempSync(join(tmpdir(), "hevy-oauth-")), "blocker");
		writeFileSync(blocker, "not a directory");
		vi.spyOn(console, "error").mockImplementation(() => {});
		const broken = new OAuthStore({
			persistencePath: join(blocker, "nested", "store.json"),
		});
		expect(broken.persistent).toBe(true);
		expect(broken.persistenceWritable).toBe(false);

		const memoryOnly = new OAuthStore();
		expect(memoryOnly.persistent).toBe(false);
		expect(memoryOnly.persistenceWritable).toBe(false);
	});

	it("keeps working when the store file cannot be written", () => {
		// A regular file standing where a directory must be makes every write
		// fail, which is the shape of a misconfigured volume mount.
		const blocker = join(mkdtempSync(join(tmpdir(), "hevy-oauth-")), "blocker");
		writeFileSync(blocker, "not a directory");
		const store = new OAuthStore({
			persistencePath: join(blocker, "nested", "store.json"),
		});
		vi.spyOn(console, "error").mockImplementation(() => {});
		store.putGrant(grant());
		// Persistence is best-effort; the in-memory record must still be usable.
		expect(store.getGrant("grant-1")).toBeDefined();
		expect(console.error).toHaveBeenCalled();
	});
});
