/**
 * WardenError — structured error for Warden auth.
 */
export class WardenError extends Error {
	readonly code: string;
	readonly hint?: string;
	/**
	 * Optional HTTP status carried by the error so the HTTP layer can map it
	 * (e.g. an authorization failure carries 403 — Epic 56 / story 56.2, D2).
	 * Additive and optional: callers that omit it behave exactly as before.
	 */
	readonly status?: number;

	constructor(
		code: string,
		message: string,
		options?: { hint?: string; status?: number },
	) {
		super(message);
		this.name = "WardenError";
		// Warden's own codes carry the `WARDEN_` namespace. The AdonisJS auth
		// identifiers (`E_UNAUTHORIZED_ACCESS`, `E_INVALID_CREDENTIALS`) are
		// PRESERVED verbatim so the exposed `.code` matches Adonis exactly — a
		// consumer branching on `error.code === 'E_UNAUTHORIZED_ACCESS'` (or a
		// framework mapping the Adonis id) sees the same string it would under
		// `@adonisjs/auth`. Documented deviation from the blanket prefix.
		this.code = code.startsWith("E_") ? code : `WARDEN_${code}`;
		this.hint = options?.hint;
		this.status = options?.status;
	}
}

/**
 * `E_UNAUTHORIZED_ACCESS` — raised when an incoming request cannot be
 * authenticated (AdonisJS `@adonisjs/auth` parity). Carries `guardDriverName`
 * (the guard that rejected) and, for session-guard flows, an optional
 * `redirectTo` (the login route an HTML client is redirected to). Status 401.
 *
 * Content negotiation (redirect for `Accept: text/html` + session guard, else
 * 401 JSON) is performed by Warden itself — see `renderAuthError` in
 * `middleware.ts` — so the package stays agnostic of the host's exception
 * handler.
 */
export class E_UNAUTHORIZED_ACCESS extends WardenError {
	readonly redirectTo?: string;
	readonly guardDriverName: string;

	constructor(
		message: string,
		options: { guardDriverName: string; redirectTo?: string },
	) {
		super("E_UNAUTHORIZED_ACCESS", message, { status: 401 });
		this.guardDriverName = options.guardDriverName;
		this.redirectTo = options.redirectTo;
	}
}

/**
 * `E_INVALID_CREDENTIALS` — raised when a credential check (email/password)
 * fails (AdonisJS parity). Status 400. Distinct from `E_UNAUTHORIZED_ACCESS`
 * (a missing/invalid session or token on a protected route → 401).
 */
export class E_INVALID_CREDENTIALS extends WardenError {
	constructor(message = "Invalid user credentials") {
		super("E_INVALID_CREDENTIALS", message, { status: 400 });
	}
}
