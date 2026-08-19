/**
 * The consent page shown to the user during authorization.
 *
 * This is the only place a Hevy API key is entered. The page is deliberately
 * self-contained — no external styles or scripts — so it renders identically
 * regardless of the deployment and so the CSP below can forbid every remote
 * resource.
 */

export const AUTHORIZE_FORM_ACTION = "/authorize";

export const HTML_RESPONSE_HEADERS = {
	"Content-Type": "text/html; charset=utf-8",
	"Cache-Control": "no-store",
	"X-Frame-Options": "DENY",
	"Referrer-Policy": "no-referrer",
	// No form-action directive: Chrome applies it to the redirect that follows
	// the submission, which would block the 302 back to the client's
	// redirect_uri (e.g. claude.ai) after approval.
	"Content-Security-Policy":
		"default-src 'none'; style-src 'unsafe-inline'; " +
		"frame-ancestors 'none'; base-uri 'none'",
} as const;

export function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

const AUTHORIZE_PAGE_STYLES = `
	:root { color-scheme: light dark; }
	body {
		font-family: system-ui, -apple-system, sans-serif;
		background: #f4f4f5; color: #18181b;
		display: flex; justify-content: center;
		margin: 0; padding: 2rem 1rem; min-height: 100vh;
		box-sizing: border-box;
	}
	main {
		background: #ffffff; border: 1px solid #e4e4e7; border-radius: 12px;
		padding: 2rem; max-width: 26rem; width: 100%;
		height: fit-content; box-sizing: border-box;
	}
	h1 { font-size: 1.25rem; margin: 0 0 1rem; }
	p { line-height: 1.5; margin: 0 0 1rem; }
	label { display: block; font-weight: 600; margin-bottom: 0.5rem; }
	input[type="password"] {
		width: 100%; box-sizing: border-box; font-size: 1rem;
		padding: 0.6rem 0.75rem; margin-bottom: 1rem;
		border: 1px solid #d4d4d8; border-radius: 8px;
		background: inherit; color: inherit;
	}
	button {
		width: 100%; font-size: 1rem; font-weight: 600;
		padding: 0.7rem; border: none; border-radius: 8px;
		background: #2563eb; color: #ffffff; cursor: pointer;
	}
	.error {
		background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c;
		border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem;
	}
	.hint { font-size: 0.875rem; color: #52525b; }
	a { color: #2563eb; }
	@media (prefers-color-scheme: dark) {
		body { background: #18181b; color: #fafafa; }
		main { background: #27272a; border-color: #3f3f46; }
		input[type="password"] { border-color: #52525b; }
		.error { background: #450a0a; border-color: #7f1d1d; color: #fca5a5; }
		.hint { color: #a1a1aa; }
	}
`;

export interface AuthorizePageOptions {
	clientName: string;
	encodedRequest: string;
	error?: string;
}

export function renderAuthorizePage(options: AuthorizePageOptions): string {
	const clientName = escapeHtml(options.clientName);
	const encodedRequest = escapeHtml(options.encodedRequest);
	const errorBanner = options.error
		? `<div class="error">${escapeHtml(options.error)}</div>`
		: "";
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect ${clientName} to Hevy</title>
<style>${AUTHORIZE_PAGE_STYLES}</style>
</head>
<body>
<main>
<h1>Connect to Hevy</h1>
<p><strong>${clientName}</strong> is requesting access to your Hevy account
through the hevy-mcp server.</p>
${errorBanner}
<form method="post" action="${AUTHORIZE_FORM_ACTION}">
<input type="hidden" name="oauth_request" value="${encodedRequest}">
<label for="hevy_api_key">Hevy API key</label>
<input type="password" id="hevy_api_key" name="hevy_api_key"
	autocomplete="off" required>
<button type="submit">Connect</button>
</form>
<p class="hint">Find your API key at
<a href="https://hevy.com/settings?developer" rel="noreferrer">
hevy.com/settings &rarr; Developer</a> (requires Hevy Pro). The key is
validated with Hevy and stored sealed for this connection only. Rotating
the key in Hevy revokes access.</p>
</main>
</body>
</html>`;
}

export function renderAuthorizeError(message: string): string {
	return (
		`<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<title>Authorization error</title></head>` +
		`<body><p>${escapeHtml(message)}</p></body></html>`
	);
}
