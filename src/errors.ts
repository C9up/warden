import type { AuthorizationResponse } from "./bouncer/AuthorizationResponse.js";

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
		// Warden's own codes are namespaced `E_WARDEN_`: `E_` because every
		// framework code carries it, the package name because `E_FORBIDDEN`
		// alone would mean three different things across the ecosystem and an
		// application could not tell them apart.
		//
		// The AdonisJS identifiers (`E_UNAUTHORIZED_ACCESS`,
		// `E_INVALID_CREDENTIALS`, bouncer's `E_AUTHORIZATION_FAILURE`) are
		// PRESERVED verbatim — they already start
		// with `E_` and fall through untouched — so a consumer branching on
		// `error.code === 'E_UNAUTHORIZED_ACCESS'` sees the same string it
		// would under `@adonisjs/auth`.
		this.code = code.startsWith("E_") ? code : `E_WARDEN_${code}`;
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
	/**
	 * The `WWW-Authenticate` value the 401 carries — a Basic guard's challenge,
	 * without which a browser never prompts for credentials.
	 */
	readonly challenge?: string;

	constructor(
		message: string,
		options: {
			guardDriverName: string;
			redirectTo?: string;
			challenge?: string;
		},
	) {
		super("E_UNAUTHORIZED_ACCESS", message, { status: 401 });
		this.guardDriverName = options.guardDriverName;
		this.redirectTo = options.redirectTo;
		this.challenge = options.challenge;
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

/**
 * The slice of an i18n service {@link E_AUTHORIZATION_FAILURE} translates
 * through: `ctx.i18n.t(identifier, data, { defaultValue })`, the shape of the
 * ecosystem's i18n package. Structural, so warden imports none.
 */
interface Translator {
	t(
		identifier: string,
		data?: Record<string, unknown>,
		options?: { defaultValue?: string },
	): string;
}

function translatorOf(ctx: unknown): Translator | undefined {
	const i18n: unknown =
		typeof ctx === "object" && ctx !== null
			? Reflect.get(ctx, "i18n")
			: undefined;
	if (typeof i18n !== "object" || i18n === null) return undefined;
	const t: unknown = Reflect.get(i18n, "t");
	if (typeof t !== "function") return undefined;
	return {
		t: (identifier, data, options) => {
			const translated: unknown = t.call(i18n, identifier, data, options);
			return typeof translated === "string"
				? translated
				: (options?.defaultValue ?? identifier);
		},
	};
}

/**
 * `E_AUTHORIZATION_FAILURE` — thrown by a denied `authorize()` (AdonisJS
 * `@adonisjs/bouncer` parity: same class name, same `code`, same
 * `identifier`). Carries the {@link AuthorizationResponse} it was thrown for,
 * so a handler reads the denial's `status`, `message` and `translation`.
 *
 * NAMED DEVIATION — upstream's class fields override what the constructor
 * passed, so its `error.message` is always "Access denied" and `error.status`
 * always 403; only its own `handle()` reads the response. Here `message` and
 * `status` ARE the response's (falling back to "Access denied" / 403), because
 * warden ships no renderer: the host's exception handler renders the error from
 * those two fields, and a `deny('Not found', 404)` must reach it as a 404.
 */
export class E_AUTHORIZATION_FAILURE extends WardenError {
	/** The i18n key looked up when the response sets no translation. */
	readonly identifier = "errors.E_AUTHORIZATION_FAILURE";
	/** The denial this error was thrown for. */
	readonly response: AuthorizationResponse;

	constructor(response: AuthorizationResponse) {
		super("E_AUTHORIZATION_FAILURE", response.message || "Access denied", {
			hint: "The current user is not authorized for this action.",
			status: response.status || 403,
		});
		this.name = "E_AUTHORIZATION_FAILURE";
		this.response = response;
	}

	/**
	 * The message to send for this denial (AdonisJS `getResponseMessage`): the
	 * response's translation when the context carries an i18n service, its
	 * message otherwise. The translation falls back to the static identifier,
	 * then to the message when the catalog has neither.
	 */
	getResponseMessage(ctx: unknown): string {
		const message = this.response.message || this.message;
		const translator = translatorOf(ctx);
		if (translator === undefined) return message;
		const identifier = this.response.translation?.identifier || this.identifier;
		const data = this.response.translation?.data || {};
		return translator.t(identifier, data, { defaultValue: message });
	}
}
