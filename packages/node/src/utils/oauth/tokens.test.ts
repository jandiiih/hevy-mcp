import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	deriveUserId,
	formatCredential,
	hasCredentialFormat,
	parseCredential,
	randomSecret,
	secretMatchesDigest,
	sha256,
	unwrapApiKey,
	verifyPkceS256,
	wrapApiKey,
} from "./tokens.js";

describe("credential encoding", () => {
	it("round-trips the three credential parts", () => {
		const credential = { userId: "u", grantId: "g", secret: "s" };
		expect(parseCredential(formatCredential(credential))).toEqual(credential);
	});

	it("rejects values that are not exactly three parts", () => {
		expect(parseCredential("a:b")).toBeNull();
		expect(parseCredential("a:b:c:d")).toBeNull();
		expect(parseCredential("a::c")).toBeNull();
		expect(parseCredential("")).toBeNull();
	});

	it("distinguishes an OAuth credential from a Hevy API key", () => {
		expect(hasCredentialFormat("user:grant:secret")).toBe(true);
		// Hevy keys are UUIDs and never contain a colon, so they take the
		// direct-API-key path instead of the OAuth path.
		expect(hasCredentialFormat("6ff8b1a0-1d3e-4f5a-9c2b-8e7d6a5b4c3d")).toBe(
			false,
		);
	});
});

describe("secretMatchesDigest", () => {
	it("accepts the matching secret and rejects everything else", () => {
		const secret = randomSecret();
		expect(secretMatchesDigest(secret, sha256(secret))).toBe(true);
		expect(secretMatchesDigest("wrong", sha256(secret))).toBe(false);
		expect(secretMatchesDigest(secret, "")).toBe(false);
	});
});

describe("API key sealing", () => {
	it("unseals only with the secret it was sealed against", () => {
		const secret = randomSecret();
		const wrapped = wrapApiKey("hevy-api-key", secret);
		expect(unwrapApiKey(wrapped, secret)).toBe("hevy-api-key");
		expect(unwrapApiKey(wrapped, randomSecret())).toBeNull();
	});

	it("never stores the key in the clear", () => {
		const secret = randomSecret();
		const wrapped = wrapApiKey("hevy-api-key", secret);
		expect(JSON.stringify(wrapped)).not.toContain("hevy-api-key");
	});

	it("detects tampering with the sealed payload", () => {
		const secret = randomSecret();
		const wrapped = wrapApiKey("hevy-api-key", secret);
		const tampered = {
			...wrapped,
			ciphertext: Buffer.from("tampered").toString("base64"),
		};
		expect(unwrapApiKey(tampered, secret)).toBeNull();
	});

	it("produces a different sealing for each call", () => {
		const secret = randomSecret();
		expect(wrapApiKey("key", secret).ciphertext).not.toBe(
			wrapApiKey("key", secret).ciphertext,
		);
	});
});

describe("deriveUserId", () => {
	it("is stable per key and different across keys", () => {
		expect(deriveUserId("key-a")).toBe(deriveUserId("key-a"));
		expect(deriveUserId("key-a")).not.toBe(deriveUserId("key-b"));
		expect(deriveUserId("key-a")).not.toContain("key-a");
	});
});

describe("verifyPkceS256", () => {
	it("accepts the verifier that produced the challenge", () => {
		const verifier = randomSecret();
		const challenge = createHash("sha256").update(verifier).digest("base64url");
		expect(verifyPkceS256(verifier, challenge)).toBe(true);
	});

	it("rejects a mismatched or empty verifier", () => {
		expect(verifyPkceS256("a", "b")).toBe(false);
		expect(verifyPkceS256("", "")).toBe(false);
	});
});
