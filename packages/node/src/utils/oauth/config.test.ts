import { describe, expect, it } from "vitest";
import { resolveOAuthConfig } from "./config.js";

describe("resolveOAuthConfig", () => {
	it("is off unless explicitly enabled", () => {
		expect(resolveOAuthConfig({})).toEqual({
			enabled: false,
			storePath: undefined,
		});
		expect(resolveOAuthConfig({ HEVY_MCP_OAUTH: "0" }).enabled).toBe(false);
		expect(resolveOAuthConfig({ HEVY_MCP_OAUTH: "" }).enabled).toBe(false);
	});

	it("accepts the usual affirmative spellings", () => {
		for (const value of ["1", "true", "TRUE", " yes "]) {
			expect(resolveOAuthConfig({ HEVY_MCP_OAUTH: value }).enabled).toBe(true);
		}
	});

	it("takes a store path only when OAuth is enabled", () => {
		expect(
			resolveOAuthConfig({
				HEVY_MCP_OAUTH: "1",
				HEVY_MCP_OAUTH_STORE_PATH: "/data/oauth.json",
			}).storePath,
		).toBe("/data/oauth.json");
		expect(
			resolveOAuthConfig({ HEVY_MCP_OAUTH_STORE_PATH: "/data/oauth.json" })
				.storePath,
		).toBeUndefined();
	});
});
