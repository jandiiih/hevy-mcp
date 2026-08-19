/**
 * OAuth discovery documents.
 *
 * A remote MCP client bootstraps entirely from these two documents: RFC 9728
 * protected-resource metadata tells it which authorization server guards this
 * MCP endpoint, and RFC 8414 authorization-server metadata tells it where to
 * register, authorize, and exchange tokens. Claude connectors fetch both
 * before showing the user a consent screen, so the URLs here must name the
 * public origin rather than the local bind address.
 */

export const AUTHORIZE_PATH = "/authorize";
export const TOKEN_PATH = "/token";
export const REGISTER_PATH = "/register";
export const PROTECTED_RESOURCE_METADATA_PATH =
	"/.well-known/oauth-protected-resource";
export const AUTHORIZATION_SERVER_METADATA_PATH =
	"/.well-known/oauth-authorization-server";
/**
 * Some clients probe the OpenID Connect discovery path first. Answering it
 * with the same document avoids a failed request before they fall back.
 */
export const OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";

export const OAUTH_SCOPES = ["mcp"] as const;

/** RFC 9728 protected-resource metadata document. */
export type ProtectedResourceMetadata = {
	resource: string;
	authorization_servers: string[];
	scopes_supported: string[];
	bearer_methods_supported: string[];
	resource_name: string;
};

/** RFC 8414 authorization-server metadata document. */
export type AuthorizationServerMetadata = {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	registration_endpoint: string;
	scopes_supported: string[];
	response_types_supported: string[];
	response_modes_supported: string[];
	grant_types_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	code_challenge_methods_supported: string[];
};

export function protectedResourceMetadata(
	origin: string,
	resourcePath: string,
): ProtectedResourceMetadata {
	return {
		resource: `${origin}${resourcePath}`,
		authorization_servers: [origin],
		scopes_supported: [...OAUTH_SCOPES],
		bearer_methods_supported: ["header"],
		resource_name: "Hevy MCP Server",
	};
}

export function authorizationServerMetadata(
	origin: string,
): AuthorizationServerMetadata {
	return {
		issuer: origin,
		authorization_endpoint: `${origin}${AUTHORIZE_PATH}`,
		token_endpoint: `${origin}${TOKEN_PATH}`,
		registration_endpoint: `${origin}${REGISTER_PATH}`,
		scopes_supported: [...OAUTH_SCOPES],
		response_types_supported: ["code"],
		response_modes_supported: ["query"],
		grant_types_supported: ["authorization_code", "refresh_token"],
		token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
		// S256 only: `plain` leaves an intercepted authorization code redeemable.
		code_challenge_methods_supported: ["S256"],
	};
}
