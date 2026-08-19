/**
 * Environment-driven configuration for the Node OAuth layer.
 *
 * OAuth is opt-in. A loopback development server and a private Docker
 * deployment behave exactly as before unless it is switched on, which keeps
 * the existing `HEVY_API_KEY` + optional static-bearer setup intact.
 */

const OAUTH_ENABLED_ENV = "HEVY_MCP_OAUTH";
const OAUTH_STORE_PATH_ENV = "HEVY_MCP_OAUTH_STORE_PATH";

export interface OAuthConfig {
	enabled: boolean;
	/** Absolute path for grant persistence, or undefined for memory-only. */
	storePath?: string;
}

function isTruthy(value: string | undefined): boolean {
	const normalized = value?.trim().toLowerCase();
	return normalized === "1" || normalized === "true" || normalized === "yes";
}

export function resolveOAuthConfig(
	env: NodeJS.ProcessEnv = process.env,
): OAuthConfig {
	const enabled = isTruthy(env[OAUTH_ENABLED_ENV]);
	const storePath = env[OAUTH_STORE_PATH_ENV]?.trim();
	return {
		enabled,
		storePath: enabled && storePath ? storePath : undefined,
	};
}
