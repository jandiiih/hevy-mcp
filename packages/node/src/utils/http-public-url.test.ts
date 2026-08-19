import { describe, expect, it } from "vitest";
import {
	configuredPublicOrigin,
	parsePublicOrigin,
	resolvePublicOrigin,
	type ForwardedRequest,
} from "./http-public-url.js";

function requestWith(headers: Record<string, string>): ForwardedRequest {
	return { headers };
}

describe("parsePublicOrigin", () => {
	it("reduces a configured URL to its origin", () => {
		expect(parsePublicOrigin("https://hevy.up.railway.app/mcp")).toBe(
			"https://hevy.up.railway.app",
		);
	});

	it("ignores values that are not usable http(s) URLs", () => {
		expect(parsePublicOrigin(undefined)).toBeUndefined();
		expect(parsePublicOrigin("   ")).toBeUndefined();
		expect(parsePublicOrigin("hevy.up.railway.app")).toBeUndefined();
		expect(parsePublicOrigin("ftp://example.com")).toBeUndefined();
	});
});

describe("resolvePublicOrigin", () => {
	it("prefers the configured origin over anything a proxy sends", () => {
		expect(
			resolvePublicOrigin(
				requestWith({ host: "internal:8080", "x-forwarded-proto": "http" }),
				{ configuredOrigin: "https://hevy.up.railway.app" },
			),
		).toBe("https://hevy.up.railway.app");
	});

	it("derives https from the forwarded protocol behind a TLS proxy", () => {
		expect(
			resolvePublicOrigin(
				requestWith({
					host: "hevy.up.railway.app",
					"x-forwarded-proto": "https",
				}),
			),
		).toBe("https://hevy.up.railway.app");
	});

	it("uses the left-most entry of a forwarded header chain", () => {
		expect(
			resolvePublicOrigin(
				requestWith({
					host: "inner.example",
					"x-forwarded-host": "public.example, inner.example",
					"x-forwarded-proto": "https, http",
				}),
			),
		).toBe("https://public.example");
	});

	it("falls back to http when no forwarded protocol is present", () => {
		expect(resolvePublicOrigin(requestWith({ host: "127.0.0.1:3000" }))).toBe(
			"http://127.0.0.1:3000",
		);
	});

	it("refuses a Host header carrying credentials or a path", () => {
		expect(
			resolvePublicOrigin(requestWith({ host: "user:pass@example.com" })),
		).toBeUndefined();
		expect(
			resolvePublicOrigin(requestWith({ host: "example.com/evil" })),
		).toBeUndefined();
	});

	it("returns undefined when there is no host at all", () => {
		expect(resolvePublicOrigin(requestWith({}))).toBeUndefined();
	});
});

describe("configuredPublicOrigin", () => {
	it("reads and normalizes HEVY_MCP_PUBLIC_URL", () => {
		expect(
			configuredPublicOrigin({
				HEVY_MCP_PUBLIC_URL: "https://example.com/mcp",
			}),
		).toBe("https://example.com");
		expect(configuredPublicOrigin({})).toBeUndefined();
	});
});
