import { describe, expect, it } from "vitest";
import {
	DEFAULT_ALLOWED_ORIGINS,
	applyCorsHeaders,
	evaluateOrigin,
	handlePreflight,
	parseAllowedOrigins,
	resolveCorsPolicy,
	type CorsRequest,
	type CorsResponse,
} from "./http-cors.js";

function requestWith(
	headers: Record<string, string>,
	method = "GET",
): CorsRequest {
	return { headers, method };
}

interface RecordingResponse extends CorsResponse {
	readonly captured: Map<string, string>;
	readonly appended: string[];
	ended: boolean;
}

function createResponse(): RecordingResponse {
	const captured = new Map<string, string>();
	const appended: string[] = [];
	return {
		captured,
		appended,
		headersSent: false,
		destroyed: false,
		statusCode: 200,
		ended: false,
		setHeader(name: string, value: string) {
			captured.set(name, value);
		},
		appendHeader(name: string, value: string) {
			appended.push(`${name}: ${value}`);
		},
		end() {
			this.ended = true;
		},
	};
}

describe("parseAllowedOrigins", () => {
	it("falls back to the built-in client allowlist", () => {
		expect(parseAllowedOrigins(undefined)).toEqual(
			new Set(DEFAULT_ALLOWED_ORIGINS),
		);
		expect(parseAllowedOrigins("  ")).toEqual(new Set(DEFAULT_ALLOWED_ORIGINS));
	});

	it("replaces the allowlist with a configured comma-separated list", () => {
		expect(parseAllowedOrigins("https://a.example, https://b.example")).toEqual(
			new Set(["https://a.example", "https://b.example"]),
		);
	});
});

describe("evaluateOrigin", () => {
	const policy = resolveCorsPolicy({});

	it("treats a missing Origin as a non-browser client", () => {
		expect(evaluateOrigin(requestWith({}), policy)).toEqual({ kind: "absent" });
	});

	it("allows the Claude web origins by default", () => {
		expect(
			evaluateOrigin(requestWith({ origin: "https://claude.ai" }), policy),
		).toEqual({ kind: "allowed", origin: "https://claude.ai" });
	});

	it("rejects an origin that is not on the allowlist", () => {
		expect(
			evaluateOrigin(requestWith({ origin: "https://evil.example" }), policy),
		).toEqual({ kind: "rejected", origin: "https://evil.example" });
	});

	it("allows the deployment's own origin", () => {
		expect(
			evaluateOrigin(
				requestWith({ origin: "https://hevy.up.railway.app" }),
				policy,
				"https://hevy.up.railway.app",
			),
		).toEqual({ kind: "allowed", origin: "https://hevy.up.railway.app" });
	});

	it("allows any origin only behind the explicit escape hatch", () => {
		const permissive = resolveCorsPolicy({
			HEVY_MCP_DISABLE_ORIGIN_CHECK: "true",
		});
		expect(
			evaluateOrigin(
				requestWith({ origin: "https://evil.example" }),
				permissive,
			),
		).toEqual({ kind: "allowed", origin: "https://evil.example" });
	});
});

describe("applyCorsHeaders", () => {
	it("exposes the session header a browser client needs to read", () => {
		const response = createResponse();
		applyCorsHeaders(response, {
			kind: "allowed",
			origin: "https://claude.ai",
		});
		expect(response.captured.get("Access-Control-Allow-Origin")).toBe(
			"https://claude.ai",
		);
		expect(response.captured.get("Access-Control-Expose-Headers")).toContain(
			"Mcp-Session-Id",
		);
		expect(response.appended).toContain("Vary: Origin");
	});

	it("sets no allow-origin for a rejected origin", () => {
		const response = createResponse();
		applyCorsHeaders(response, {
			kind: "rejected",
			origin: "https://evil.example",
		});
		expect(response.captured.has("Access-Control-Allow-Origin")).toBe(false);
	});
});

describe("handlePreflight", () => {
	it("answers an allowed preflight with the permitted methods and headers", () => {
		const response = createResponse();
		const handled = handlePreflight(
			requestWith({ origin: "https://claude.ai" }, "OPTIONS"),
			response,
			{ kind: "allowed", origin: "https://claude.ai" },
		);
		expect(handled).toBe(true);
		expect(response.statusCode).toBe(204);
		expect(response.captured.get("Access-Control-Allow-Methods")).toContain(
			"DELETE",
		);
		expect(response.captured.get("Access-Control-Allow-Headers")).toContain(
			"Authorization",
		);
	});

	it("refuses a preflight from a rejected origin", () => {
		const response = createResponse();
		handlePreflight(
			requestWith({ origin: "https://evil.example" }, "OPTIONS"),
			response,
			{ kind: "rejected", origin: "https://evil.example" },
		);
		expect(response.statusCode).toBe(403);
	});

	it("leaves non-OPTIONS requests alone", () => {
		const response = createResponse();
		expect(
			handlePreflight(requestWith({}, "POST"), response, { kind: "absent" }),
		).toBe(false);
	});
});
