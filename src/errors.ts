/**
 * Warden's errors, one per code. A caller branches on `error.code` or on
 * `error instanceof errors.E_*`.
 *
 * Warden's own codes are namespaced `E_WARDEN_`: `E_` because every framework
 * code carries it, the package name because `E_FORBIDDEN` alone would mean
 * three different things across the ecosystem. The AdonisJS identifiers
 * (`E_UNAUTHORIZED_ACCESS`, `E_INVALID_CREDENTIALS`, bouncer's
 * `E_AUTHORIZATION_FAILURE`) are kept verbatim, with their upstream statuses,
 * so a consumer branching on `error.code === 'E_UNAUTHORIZED_ACCESS'` sees the
 * string it would under `@adonisjs/auth`.
 *
 * A message too irregular for one template takes `%s`, with the text built
 * where the error is thrown.
 */

import { createError, Exception } from "@c9up/flare";
import type { AuthorizationResponse } from "./bouncer/AuthorizationResponse.js";
import {
	type NegotiatedErrorContext,
	renderNegotiated,
	renderUnauthorizedAccess,
	type UnauthorizedAccessContext,
} from "./errorResponses.js";

/**
 * `E_UNAUTHORIZED_ACCESS` — raised when an incoming request cannot be
 * authenticated (AdonisJS `@adonisjs/auth` parity). Carries `guardDriverName`
 * (the guard that rejected) and, for session-guard flows, an optional
 * `redirectTo` (the login route an HTML client is redirected to). Status 401.
 *
 * It renders itself (`handle`): warden's middleware throws it, as does
 * `ctx.auth.authenticate()` in a handler, and the host's exception handler
 * calls `handle`, so every 401 answers the same way.
 */
export class E_UNAUTHORIZED_ACCESS extends Exception {
	static override status = 401;
	static override code = "E_UNAUTHORIZED_ACCESS";

	/** The translation key of the message (`ctx.i18n.t`). */
	readonly identifier = "errors.E_UNAUTHORIZED_ACCESS";

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
		super(message);
		this.guardDriverName = options.guardDriverName;
		this.redirectTo = options.redirectTo;
		this.challenge = options.challenge;
	}

	/** The message, translated through `ctx.i18n` when the request has one. */
	getResponseMessage(error: E_UNAUTHORIZED_ACCESS, ctx: unknown): string {
		return translate(ctx, error.identifier, {}, error.message);
	}

	/**
	 * Write the refusal: an HTML request against a session guard with a
	 * `redirectTo` is redirected to the login route; otherwise the guard's
	 * `WWW-Authenticate` challenge when it has one, and
	 * `401 { error: { code, message } }`.
	 *
	 * DEVIATION (named): upstream picks a renderer per guard driver (a flash
	 * and an intended-URL redirect for `session`, the challenge with the
	 * message as text for `basic_auth`, negotiated text / `{ errors }` for
	 * `access_tokens`). warden keeps the one response its middleware has
	 * always written, for every guard, so no client sees a new shape.
	 */
	async handle(
		error: E_UNAUTHORIZED_ACCESS,
		ctx: UnauthorizedAccessContext,
	): Promise<void> {
		renderUnauthorizedAccess(ctx, error, error.getResponseMessage(error, ctx));
	}
}

/**
 * `E_INVALID_CREDENTIALS` — raised when a credential check (email/password)
 * fails (AdonisJS parity). Status 400. Distinct from `E_UNAUTHORIZED_ACCESS`
 * (a missing/invalid session or token on a protected route → 401).
 */
export class E_INVALID_CREDENTIALS extends Exception {
	static override status = 400;
	static override code = "E_INVALID_CREDENTIALS";
	static override message = "Invalid user credentials";

	/** The translation key of the message (`ctx.i18n.t`). */
	readonly identifier = "errors.E_INVALID_CREDENTIALS";

	/** The message, translated through `ctx.i18n` when the request has one. */
	getResponseMessage(error: E_INVALID_CREDENTIALS, ctx: unknown): string {
		return translate(ctx, error.identifier, {}, error.message);
	}

	/**
	 * Write the refusal by content negotiation: a browser with a session gets
	 * the form flashed back (without `_csrf`, `_method` and passwords), the
	 * message flashed, and a redirect back; without a session, the message as
	 * text; `{ errors: [{ message }] }` for JSON; a JSON:API error object.
	 */
	async handle(
		error: E_INVALID_CREDENTIALS,
		ctx: NegotiatedErrorContext,
	): Promise<void> {
		renderNegotiated(
			ctx,
			{
				status: error.status,
				code: error.code ?? E_INVALID_CREDENTIALS.code,
				message: error.getResponseMessage(error, ctx),
			},
			{
				flashExcept: ["_csrf", "_method", "password", "password_confirmation"],
				redirectBack: true,
			},
		);
	}
}

/**
 * Thrown by `WebauthnCredentialStore.save` when the credential id is already
 * registered. `finishRegistration` turns it into `{ verified: false }`; any
 * other error from the store is an outage and propagates.
 */
export class E_WARDEN_WEBAUTHN_CREDENTIAL_EXISTS extends createError<
	[credentialId: string]
>(
	'The WebAuthn credential "%s" is already registered.',
	"E_WARDEN_WEBAUTHN_CREDENTIAL_EXISTS",
) {
	static override help =
		"A credential id belongs to the account that registered it first. Keep it unique in the store (INSERT, never upsert).";
}

/**
 * `AuthManager` is not in the container; add `WardenProvider` to the
 * providers.
 */
export const E_WARDEN_AUTH_NOT_REGISTERED = createError(
	"AuthManager is not registered in the container — add WardenProvider to your providers list.",
	"E_WARDEN_AUTH_NOT_REGISTERED",
);

/**
 * Every attempted guard crashed (a database down, a bug): a server incident,
 * distinct from a credential rejection.
 */
export const E_WARDEN_AUTH_STRATEGY_ERROR = createError(
	"Authentication unavailable — one or more strategies failed. Check server logs.",
	"E_WARDEN_AUTH_STRATEGY_ERROR",
);

/** `JwtStrategy.revoke()` on a guard built without a `blacklist`. */
export const E_WARDEN_BLACKLIST_REQUIRED = createError(
	"JwtStrategy.revoke() requires a `blacklist` driver. Pass `{ blacklist: new TokenBlacklist(driver) }` to the constructor.",
	"E_WARDEN_BLACKLIST_REQUIRED",
);

/**
 * The quasar connection lacks a command the token blacklist issues (`set`,
 * `exists`).
 */
export const E_WARDEN_INCOMPLETE_CONNECTION = createError<[message: string]>(
	"%s",
	"E_WARDEN_INCOMPLETE_CONNECTION",
);

/** `Bouncer.ability()` was given options without a callback. */
export class E_WARDEN_INVALID_ABILITY extends createError(
	"Bouncer.ability requires a callback alongside the options object.",
	"E_WARDEN_INVALID_ABILITY",
) {
	static override help = "Bouncer.ability({ allowGuest: true }, (user) => ...)";
}

/** A guard, token, MFA or rate-limit setting is invalid. */
export const E_WARDEN_INVALID_CONFIG = createError<[message: string]>(
	"%s",
	"E_WARDEN_INVALID_CONFIG",
);

/** A stored WebAuthn public key is malformed. */
export const E_WARDEN_INVALID_CREDENTIAL = createError(
	"stored COSE key is malformed",
	"E_WARDEN_INVALID_CREDENTIAL",
);

/** A duration string does not parse, or names an unknown unit. */
export const E_WARDEN_INVALID_DURATION = createError<[message: string]>(
	"%s",
	"E_WARDEN_INVALID_DURATION",
);

/**
 * The secret given to `TotpProvider.generate()` / `verify()` is not base32.
 */
export const E_WARDEN_INVALID_TOTP_SECRET = createError<[unknown]>(
	"Invalid base32 character: %s",
	"E_WARDEN_INVALID_TOTP_SECRET",
);

/**
 * The Rust JWT engine is not loaded. The message names the platform package
 * to install; the load error is its `cause`.
 */
export const E_WARDEN_NAPI_REQUIRED = createError<[fix: string]>(
	"The Rust warden-engine binary is required.\n  Fix: %s",
	"E_WARDEN_NAPI_REQUIRED",
);

/**
 * The `AuthManager` singleton was used before `WardenProvider.boot()` ran.
 */
export const E_WARDEN_NOT_BOOTED = createError(
	"[warden] AuthManager singleton accessed before WardenProvider.boot() ran. Check that `@c9up/warden/provider` is listed in your reamrc.ts providers.",
	"E_WARDEN_NOT_BOOTED",
);

/** `WardenProvider` booted without any guard configured. */
export const E_WARDEN_NO_AUTH_CONFIG = createError(
	"@c9up/warden: no authentication guards configured. Set config.warden.auth.guards (AdonisJS form) or at least one of .jwt / .session / .apiKey in your reamrc.ts before registering WardenProvider.",
	"E_WARDEN_NO_AUTH_CONFIG",
);

/**
 * A session guard's `login()` / `logout()` ran without `ctx.session`;
 * register the session middleware first.
 */
export const E_WARDEN_NO_SESSION = createError<[unknown]>(
	"Guard '%s'.login()/logout() requires a session, but ctx.session is unset. Register the session middleware upstream.",
	"E_WARDEN_NO_SESSION",
);

/** The OTP challenge store does not implement `take()`. */
export class E_WARDEN_OTP_STORE_CONTRACT extends createError(
	"The OTP challenge store does not implement take().",
	"E_WARDEN_OTP_STORE_CONTRACT",
) {
	static override help =
		"take(id) must remove the challenge AND return it in ONE indivisible operation — `DELETE ... RETURNING` on SQL, GETDEL or a Lua script on Redis. Reading then deleting separately lets two requests with the same correct code both succeed.";
}

/** The refresh token store cannot rotate: no `consume()` or no `revokeFamily()`. */
export class E_WARDEN_REFRESH_STORE_CONTRACT extends createError(
	"The refresh token store does not implement consume() and revokeFamily().",
	"E_WARDEN_REFRESH_STORE_CONTRACT",
) {
	static override help =
		"consume(familyId, presentedHash, successor) must replace the family's hash ONLY if it is still the one presented, in ONE indivisible operation — `UPDATE ... WHERE family_id = ? AND hash = ?` and the affected row count on SQL, a Lua script on Redis — and revokeFamily(familyId) must remove the family's row. Reading then writing separately lets two requests redeem the same refresh token.";
}

/**
 * `E_WARDEN_MFA_REQUIRED` — the request did not complete the MFA step-up and
 * the operation needs it: a change to the factors of an account that already
 * has a confirmed one (`MfaManager`). Status 403.
 *
 * Same code, status, message and body as the refusal of a `@RequireMfa()`
 * route, so an application branches on one code whichever raised it.
 */
export class E_WARDEN_MFA_REQUIRED extends Exception {
	static override status = 403;
	static override code = "E_WARDEN_MFA_REQUIRED";
	static override message =
		"Multi-factor authentication is required for this action.";

	/** Write the refusal: `403 { error: { code, message } }`. */
	async handle(
		error: E_WARDEN_MFA_REQUIRED,
		ctx: {
			response: { status(code: number): unknown; json(data: unknown): void };
		},
	): Promise<void> {
		ctx.response.status(error.status);
		ctx.response.json({
			error: {
				code: error.code ?? E_WARDEN_MFA_REQUIRED.code,
				message: error.message,
			},
		});
	}
}

/**
 * `@Guard()`, `@Role()` or `@Permission()` names nothing to require. Thrown
 * when the decorator is applied, and by warden's middleware for an action
 * whose metadata names nothing: an empty requirement would leave the action
 * open to every request.
 */
export class E_WARDEN_EMPTY_GATE_REQUIREMENT extends createError<
	[action: string, decorator: string]
>(
	"%s: %s names nothing to require, so it would leave the action open to every request.",
	"E_WARDEN_EMPTY_GATE_REQUIREMENT",
) {
	static override help =
		"Name at least one guard, role or permission — `@Guard('jwt')`, `@Role('admin')` — or remove the decorator. A list read from configuration must not be empty.";
}

/** The in-memory OTP store holds its maximum of pending challenges. */
export class E_WARDEN_OTP_STORE_FULL extends createError<[unknown]>(
	"The in-memory OTP store is full (%s pending challenges).",
	"E_WARDEN_OTP_STORE_FULL",
) {
	static override help =
		"Rate-limit the endpoint that mints codes, or move to a persistent store with its own TTL.";
}

/**
 * The container resolved a policy to something that is not an instance of
 * its class.
 */
export const E_WARDEN_POLICY_RESOLUTION_FAILED = createError<[unknown]>(
	'The container resolved "%s" to something else — a policy must be an instance of the class that was requested.',
	"E_WARDEN_POLICY_RESOLUTION_FAILED",
);

/**
 * A Redis token blacklist names a quasar connection and `@c9up/quasar` is
 * not installed, or its provider has not booted.
 */
export const E_WARDEN_QUASAR_MISSING = createError<[message: string]>(
	"%s",
	"E_WARDEN_QUASAR_MISSING",
);

/** Remember-me was asked and no remember-me tokens are configured. */
export const E_WARDEN_REMEMBER_ME_UNAVAILABLE = createError<[message: string]>(
	"%s",
	"E_WARDEN_REMEMBER_ME_UNAVAILABLE",
);

/** A challenge store `maxEntries` is not a positive integer. */
export class E_WARDEN_STORE_LIMIT_INVALID extends createError<[unknown]>(
	"maxEntries must be a positive integer, got %s.",
	"E_WARDEN_STORE_LIMIT_INVALID",
) {
	static override help =
		"Pass the number of pending entries this process may hold — the default is 10_000.";
}

/** A challenge store `ttlMs` is not a positive integer. */
export class E_WARDEN_STORE_TTL_INVALID extends createError<[unknown]>(
	"ttlMs must be a positive integer, got %s.",
	"E_WARDEN_STORE_TTL_INVALID",
) {
	static override help =
		"Give the ceremony a lifetime in milliseconds — the default is 300000 (5 min).";
}

/**
 * `authenticate()` with credentials on an API key guard; the token goes to
 * `verify()`.
 */
export const E_WARDEN_STRATEGY_CANNOT_AUTHENTICATE = createError(
	"ApiKeyStrategy does not support credential-based auth. Use verify() with the access token.",
	"E_WARDEN_STRATEGY_CANNOT_AUTHENTICATE",
);

/** `issueFor()` on a guard that does not mint tokens. */
export const E_WARDEN_STRATEGY_CANNOT_ISSUE = createError<[message: string]>(
	"%s",
	"E_WARDEN_STRATEGY_CANNOT_ISSUE",
);

/** `login()` / `logout()` on a stateless guard (JWT, API key). */
export const E_WARDEN_STRATEGY_CANNOT_LOGIN = createError<[message: string]>(
	"%s",
	"E_WARDEN_STRATEGY_CANNOT_LOGIN",
);

/**
 * A guard has no `authenticateAsClient()`, so it cannot forge a client
 * request in tests.
 */
export const E_WARDEN_STRATEGY_HAS_NO_CLIENT = createError<[message: string]>(
	"%s",
	"E_WARDEN_STRATEGY_HAS_NO_CLIENT",
);

/** A guard name is not configured. */
export class E_WARDEN_STRATEGY_NOT_FOUND extends createError<[unknown]>(
	"Auth strategy '%s' not registered",
	"E_WARDEN_STRATEGY_NOT_FOUND",
) {
	static override help =
		"Call registerStrategy() before using this strategy name.";
}

/**
 * The template engine is installed but `@can` / `@cannot` cannot be
 * registered on it.
 */
export class E_WARDEN_TEMPLATE_ENGINE_UNUSABLE extends createError<[unknown]>(
	"The template engine is installed but @can / @cannot cannot be registered: %s",
	"E_WARDEN_TEMPLATE_ENGINE_UNUSABLE",
) {
	static override help =
		"`@c9up/inker` must default-export its plugin registrar (`inker.use(plugin)`), whose plugins receive an engine with `registerTag()`.";
}

/**
 * A token lifetime (a refresh token's TTL, an access token's lifetime) is
 * not a positive finite number; a token lifetime must also be whole seconds.
 */
export const E_WARDEN_TOKEN_TTL_INVALID = createError<[message: string]>(
	"%s",
	"E_WARDEN_TOKEN_TTL_INVALID",
);

/** No ability of this name is registered on the bouncer. */
export class E_WARDEN_UNKNOWN_ABILITY extends createError<[unknown]>(
	'No ability "%s" is registered on this Bouncer.',
	"E_WARDEN_UNKNOWN_ABILITY",
) {
	static override help =
		"Register it via new Bouncer(user, { [name]: ability }).";
}

/** No policy of this name is registered on the bouncer. */
export class E_WARDEN_UNKNOWN_POLICY extends createError<[unknown]>(
	'No policy "%s" is registered on this Bouncer.',
	"E_WARDEN_UNKNOWN_POLICY",
) {
	static override help =
		"Register it via new Bouncer(user, abilities, { [name]: Policy }).";
}

/** A policy has no method for the action. */
export class E_WARDEN_UNKNOWN_POLICY_ACTION extends createError<
	[unknown, unknown]
>('Policy "%s" has no action "%s"', "E_WARDEN_UNKNOWN_POLICY_ACTION") {
	static override help = "Declare the action as a method on the policy class.";
}

/**
 * The session guard has no credential step. Verify the password yourself,
 * then call `login(user)`.
 */
export class E_WARDEN_USE_LOGIN extends createError(
	"SessionStrategy has no credential step. Verify the password yourself, then start the session via authManager.login(user, session) (or ctx.auth.use('session').login(user)).",
	"E_WARDEN_USE_LOGIN",
) {
	static override help =
		"Verify the password yourself (e.g. via @c9up/sigil Hash.verify), then call authManager.login(user, session) — SessionStrategy.login(user, session) also works directly.";
}

/**
 * The in-memory WebAuthn challenge store holds its maximum of pending
 * ceremonies.
 */
export class E_WARDEN_WEBAUTHN_STORE_FULL extends createError<[unknown]>(
	"The in-memory WebAuthn challenge store is full (%s pending ceremonies).",
	"E_WARDEN_WEBAUTHN_STORE_FULL",
) {
	static override help =
		"Rate-limit the endpoint that starts a ceremony, or move to a persistent store with its own TTL.";
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

/** `identifier` translated through `ctx.i18n`, `fallback` without one. */
function translate(
	ctx: unknown,
	identifier: string,
	data: Record<string, unknown>,
	fallback: string,
): string {
	const translator = translatorOf(ctx);
	if (translator === undefined) return fallback;
	return translator.t(identifier, data, { defaultValue: fallback });
}

/** The methods of a form submission, which a denial redirects back from. */
const FORM_SUBMISSION_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

/**
 * `E_AUTHORIZATION_FAILURE` — thrown by a denied `authorize()` (AdonisJS
 * `@adonisjs/bouncer` parity: same class name, same `code`, same
 * `identifier`). Carries the {@link AuthorizationResponse} it was thrown for,
 * so a handler reads the denial's `status`, `message` and `translation`.
 *
 * NAMED DEVIATION — upstream's class fields override what the constructor
 * passed, so its `error.message` is always "Access denied" and `error.status`
 * always 403; only its own `handle()` reads the response. Here `message` and
 * `status` ARE the response's (falling back to "Access denied" / 403), so a
 * host's exception handler that renders the error from those two fields
 * without calling `handle` still answers a `deny('Not found', 404)` as a 404.
 */
export class E_AUTHORIZATION_FAILURE extends Exception {
	static override code = "E_AUTHORIZATION_FAILURE";
	static override status = 403;
	static override message = "Access denied";
	static override help = "The current user is not authorized for this action.";

	/** The i18n key looked up when the response sets no translation. */
	readonly identifier = "errors.E_AUTHORIZATION_FAILURE";
	/** The denial this error was thrown for. */
	readonly response: AuthorizationResponse;

	constructor(response: AuthorizationResponse) {
		super(response.message || undefined, {
			status: response.status || undefined,
		});
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

	/**
	 * Write the denial by content negotiation, with the response's status: a
	 * form submission (POST, PUT, PATCH, DELETE) from a browser with a session
	 * gets the form flashed back (without `_csrf`, `_method` and passwords),
	 * the message flashed, and a redirect back; any other HTML request the
	 * message as text; `{ errors: [{ message }] }` for JSON; a JSON:API error
	 * object.
	 */
	async handle(_: unknown, ctx: NegotiatedErrorContext): Promise<void> {
		const method =
			typeof ctx.request.method === "function" ? ctx.request.method() : "";
		renderNegotiated(
			ctx,
			{
				status: this.response.status || this.status,
				code: E_AUTHORIZATION_FAILURE.code,
				message: this.getResponseMessage(ctx),
			},
			{
				flashExcept: [
					"_csrf",
					"_method",
					"password",
					"password_confirmation",
					"passwordConfirmation",
				],
				redirectBack: FORM_SUBMISSION_METHODS.includes(method.toUpperCase()),
			},
		);
	}
}
