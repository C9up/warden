/**
 * Authenticator — a PER-REQUEST authentication contract (AdonisJS
 * `@adonisjs/auth` `Authenticator` parity), attached as `ctx.auth`.
 *
 * Why it exists: before this, `ctx.auth` was a plain data object with no
 * methods, so an INLINE route handler (`router.post('/login', handler)`) had no
 * way to authenticate on demand — only the `@Guard` decorator path worked, and
 * that reads `ctx.route.controller/action`, which inline/functional routes don't
 * expose. This contract makes `await ctx.auth.authenticate()` /
 * `ctx.auth.use('session').login(user)` work anywhere, exactly like Adonis.
 *
 * Warden stays agnostic: the Authenticator is built from the {@link AuthManager}
 * (resolved via `ctx.containerResolver`) + the request `ctx`; it never imports
 * `@c9up/ream`.
 */

import type {
	AuthManager,
	AuthResult,
	AuthStrategy,
	UserPayload,
} from "./AuthManager.js";
import { E_UNAUTHORIZED_ACCESS, WardenError } from "./errors.js";
import type { WardenContext } from "./middleware.js";
import { sanitizePayload } from "./sanitize.js";
import {
	createSessionGuardState,
	type SessionGuardState,
	type SessionStore,
} from "./strategies/SessionStrategy.js";

/**
 * Guard names Warden accepts for the API-key / access-tokens driver. AdonisJS
 * names the driver `access_tokens`; the legacy `api-key` spelling stays valid so
 * existing `@Guard('api-key')` routes and configs keep working.
 */
export const API_KEY_GUARD_NAMES: readonly string[] = [
	"access_tokens",
	"api-key",
];

interface StrategyWithContext extends AuthStrategy {
	verifyWithContext(token: string, ctx: unknown): Promise<AuthResult>;
}

/**
 * The strategy behind a guard name, or `undefined` when nothing is registered
 * under it.
 *
 * `getStrategy()` throws for an unknown name — correct when an application
 * asks for a guard by name, wrong here: this is a capability probe across a
 * list, and a name that resolves to nothing simply is not a session guard.
 */
function strategyOrUndefined(
	auth: AuthManager,
	name: string,
): AuthStrategy | undefined {
	try {
		return auth.getStrategy(name);
	} catch {
		return undefined;
	}
}

/**
 * A guard that can keep a user signed in: mint a token, name its cookie, read
 * one back, and seat the session that follows.
 */
interface RememberMeIssuer {
	issueRememberMeToken(user: UserPayload): Promise<string | null>;
	authenticateViaRememberMeToken(
		cookieValue: unknown,
		state?: SessionGuardState,
	): Promise<{ user: UserPayload; cookieValue: string } | null>;
	seatSession(user: UserPayload, session: SessionStore): void;
	revokeRememberMeToken(cookieValue: unknown): Promise<void>;
	readonly rememberMeCookieName: string;
	readonly rememberMeAgeSeconds: number;
}

/**
 * Structural, like every other capability probe here: a guard an application
 * wrote itself, carrying the same three members, keeps users signed in just as
 * well as the one shipped with the package.
 */
function isRememberMeIssuer(
	strategy: AuthStrategy,
): strategy is AuthStrategy & RememberMeIssuer {
	return (
		typeof Reflect.get(strategy, "issueRememberMeToken") === "function" &&
		typeof Reflect.get(strategy, "authenticateViaRememberMeToken") ===
			"function" &&
		typeof Reflect.get(strategy, "seatSession") === "function" &&
		typeof Reflect.get(strategy, "revokeRememberMeToken") === "function" &&
		typeof Reflect.get(strategy, "rememberMeCookieName") === "string" &&
		typeof Reflect.get(strategy, "rememberMeAgeSeconds") === "number"
	);
}

/** Whether the guard behind `name` authenticates from the request context. */
function isSessionGuard(auth: AuthManager, name: string): boolean {
	const strategy = strategyOrUndefined(auth, name);
	return strategy !== undefined && hasVerifyWithContext(strategy);
}

function hasVerifyWithContext(
	strategy: AuthStrategy,
): strategy is StrategyWithContext {
	return (
		typeof (strategy as StrategyWithContext).verifyWithContext === "function"
	);
}

/** The credentials Warden extracts from a request, independent of guard list. */
export interface ExtractedCredentials {
	bearerToken: string;
	apiKey: string;
	session: SessionStore | undefined;
}

/**
 * Resolve the header the API-key guard reads its key from. Prefers the
 * registered guard's `headerName` (under either accepted guard name), else the
 * `x-api-key` default. Never throws.
 */
function resolveApiKeyHeader(auth: AuthManager): string {
	for (const name of API_KEY_GUARD_NAMES) {
		try {
			const s = auth.getStrategy(name);
			const header = "headerName" in s ? s.headerName : undefined;
			if (typeof header === "string" && header.length > 0) return header;
		} catch {
			// Guard not registered under this name — try the next.
		}
	}
	return "x-api-key";
}

/**
 * Extract the request's credentials once — a Bearer token, an API key (read from
 * the configured header, matched case-insensitively), and the session store.
 * Shared by `wardenMiddleware`, `silentAuth`, and the Authenticator so all three
 * read credentials identically.
 */
export function extractCredentials(
	ctx: WardenContext,
	auth: AuthManager,
): ExtractedCredentials {
	const headers = ctx.request.headers();
	const authHeader = headers.authorization ?? "";
	const bearerToken = authHeader.startsWith("Bearer ")
		? authHeader.slice(7)
		: "";
	// HTTP header names are case-insensitive; runtimes lowercase incoming keys,
	// so normalise the configured header name before the lookup.
	const apiKey = headers[resolveApiKeyHeader(auth).toLowerCase()] ?? "";
	return { bearerToken, apiKey, session: ctx.session };
}

/** Outcome of {@link tryAuthenticate}. */
export interface AuthAttempt {
	result: AuthResult | null;
	/** Name of the guard that authenticated (only when `result.authenticated`). */
	viaGuard?: string;
	attemptCount: number;
	crashCount: number;
}

/**
 * Try each declared guard in order — session guards via `verifyWithContext()`,
 * others via `verify(token)` with native-first credential fallback.
 * Distinguishes crashes (strategy threw / `strategyCrash`) from credential
 * rejections so the caller can return 500 vs 401.
 */
export async function tryAuthenticate(
	auth: AuthManager,
	strategies: string[],
	creds: {
		bearerToken: string;
		apiKey: string;
		session: SessionStore | undefined;
	},
): Promise<AuthAttempt> {
	const { bearerToken, apiKey, session } = creds;
	let result: AuthResult | null = null;
	let viaGuard: string | undefined;
	let attemptCount = 0;
	let crashCount = 0;
	for (const strategyName of strategies) {
		try {
			let r: AuthResult;
			// A session guard is one that can verify FROM THE REQUEST CONTEXT,
			// not one registered under a particular name. `guards: { web:
			// sessionGuard(...) }` is the documented config shape, and matching
			// on the literal "session" sent it down the bearer-token path — so
			// `auth.use('web').authenticate()` never read the session at all.
			const strategy = strategyOrUndefined(auth, strategyName);
			const verifyWithContext =
				strategy && hasVerifyWithContext(strategy)
					? strategy.verifyWithContext
					: undefined;
			if (verifyWithContext !== undefined) {
				attemptCount++;
				r = await verifyWithContext.call(strategy, "", { session });
				// The session path bypasses AuthManager.verify(), so apply the
				// same prototype-pollution guard JWT / api-key users get there.
				if (r.user) sanitizePayload(r.user);
			} else {
				// Native-first credential, other transport as fallback so a
				// single-credential client still authenticates (and an invalid
				// Bearer no longer masks a valid API key for the api-key guard).
				const credential = API_KEY_GUARD_NAMES.includes(strategyName)
					? apiKey || bearerToken
					: bearerToken || apiKey;
				if (!credential) continue;
				attemptCount++;
				r = await auth.verify(credential, strategyName);
			}
			if (r.authenticated) {
				result = r;
				viaGuard = strategyName;
				break;
			}
			if (r.strategyCrash === true) {
				crashCount++;
				console.error(
					`[warden] strategy '${strategyName}' threw during verify(): ${r.error ?? "unknown error"}`,
				);
			}
		} catch (err) {
			// AuthManager rethrows structured WardenError sentinels — treat these
			// as crashes too (config errors, SessionStrategy.USE_LOGIN, etc.).
			crashCount++;
			console.error(
				`[warden] strategy '${strategyName}' threw during verify():`,
				err,
			);
		}
	}
	return { result, viaGuard, attemptCount, crashCount };
}

/**
 * A named-guard accessor (AdonisJS `auth.use('web')`). Exposes the stateful
 * `login()`/`logout()` for session guards plus per-guard `authenticate()`.
 */
export class GuardAccessor {
	readonly #ctx: WardenContext;
	readonly #auth: AuthManager;
	readonly #name: string;
	readonly #parent: Authenticator;
	/**
	 * The session-guard flags for THIS request. They live on the accessor —
	 * which the Authenticator builds and caches per request — and never on the
	 * strategy, which is built once from config and shared by every request.
	 */
	readonly #state: SessionGuardState = createSessionGuardState();

	constructor(
		ctx: WardenContext,
		auth: AuthManager,
		name: string,
		parent: Authenticator,
	) {
		this.#ctx = ctx;
		this.#auth = auth;
		this.#name = name;
		this.#parent = parent;
	}

	/** The user, only if the request authenticated via THIS guard. */
	get user(): UserPayload | undefined {
		return this.#parent.authenticatedViaGuard === this.#name
			? this.#parent.user
			: undefined;
	}

	get isAuthenticated(): boolean {
		return this.user !== undefined;
	}

	/**
	 * Whether the user was revived from a remember-me cookie rather than
	 * signing in.
	 *
	 * This is the distinction that lets an app demand the password again before
	 * something sensitive — changing an email, spending money, deleting an
	 * account.
	 */
	get viaRemember(): boolean {
		return this.#state.viaRemember;
	}

	/** Whether a remember-me cookie was tried at all on this request. */
	get attemptedViaRemember(): boolean {
		return this.#state.attemptedViaRemember;
	}

	/**
	 * Whether `logout()` has run during this request.
	 *
	 * A handler that logs out and then keeps working — clearing a cart, writing
	 * an audit line — could not otherwise tell the session was already gone.
	 */
	get isLoggedOut(): boolean {
		return this.#state.isLoggedOut;
	}

	/**
	 * Revive the user from a remember-me cookie, recording on this request that
	 * one was tried and whether it worked.
	 *
	 * The returned `cookieValue` must replace the one the browser holds: the
	 * token is single-use and is recycled on every successful revival.
	 */
	authenticateViaRememberMeToken(
		cookieValue: unknown,
	): Promise<{ user: UserPayload; cookieValue: string } | null> {
		return this.#auth.authenticateViaRememberMeToken(
			cookieValue,
			this.#name,
			this.#state,
		);
	}

	/** Authenticate the request using only this guard (throws on failure). */
	authenticate(): Promise<void> {
		return this.#parent.authenticateUsing([this.#name]);
	}

	/**
	 * Revive this request from the remember-me cookie, if the browser holds one.
	 *
	 * The token is single-use: a success recycles the cookie and re-seats the
	 * session, so a stolen copy stops working the moment the real user comes
	 * back, and the rest of the request sees an ordinary signed-in user.
	 */
	async tryRememberMeCookie(): Promise<UserPayload | undefined> {
		const read = this.#ctx.request.encryptedCookie;
		const write = this.#ctx.response.encryptedCookie;
		const session = this.#ctx.session;
		if (!read || !write || !session) return undefined;

		const strategy = strategyOrUndefined(this.#auth, this.#name);
		if (!strategy || !isRememberMeIssuer(strategy)) return undefined;

		const cookie = read.call(this.#ctx.request, strategy.rememberMeCookieName);
		if (!cookie) return undefined;

		const revived = await strategy.authenticateViaRememberMeToken(
			cookie,
			this.#state,
		);
		if (!revived) return undefined;

		write.call(
			this.#ctx.response,
			strategy.rememberMeCookieName,
			revived.cookieValue,
			{ maxAge: strategy.rememberMeAgeSeconds, httpOnly: true },
		);
		// Seat the session WITHOUT `login()`: that method means a password was
		// typed, and it clears `viaRemember` — the one thing this path exists to
		// report, and what an app checks before letting someone change an email
		// or spend money.
		strategy.seatSession(revived.user, session);
		return revived.user;
	}

	/**
	 * Log a user in through this guard (session guards).
	 *
	 * `remember` mints a remember-me token and writes it as an ENCRYPTED,
	 * httpOnly cookie — the cookie IS the credential, so anyone who can read it
	 * can present it. Without `remember`, any cookie the browser still holds is
	 * cleared: signing in without ticking the box has to REVOKE the standing
	 * permission, not leave it in place.
	 */
	async login(user: UserPayload, remember = false): Promise<void> {
		const session = this.#requireSession();
		const issued = remember ? await this.#issueRememberMe(user) : undefined;
		if (!remember) this.#clearRememberMe();
		try {
			await this.#auth.login(user, session, this.#name, this.#state);
		} catch (err) {
			// The token is minted and the cookie sent before the session is
			// seated — upstream's order, and it has to be, because the cookie
			// belongs on the same response.
			//
			// NAMED DEVIATION — upstream does not roll any of this back; it has
			// no need to, because its session write is a map assignment that
			// cannot fail. Here `login()` also fires listeners, any of which
			// can throw, so the window is real.
			//
			// And clearing the cookie is not enough: the token was PERSISTED,
			// and its value reached the wire, where it may have been captured
			// — a proxy log, an already-flushed response. Revoking the row is
			// what makes a failed sign-in leave nothing usable behind.
			if (issued !== undefined) await this.#revokeRememberMe(issued);
			throw err;
		}
	}

	/** Undo an issued remember-me: the stored row first, then the cookie. */
	async #revokeRememberMe(value: string): Promise<void> {
		const strategy = strategyOrUndefined(this.#auth, this.#name);
		if (strategy && isRememberMeIssuer(strategy)) {
			// Best-effort: a store that is itself down must not replace the
			// caller's error with its own.
			await strategy.revokeRememberMeToken(value).catch(() => undefined);
		}
		this.#clearRememberMe();
	}

	/**
	 * Mint the token and put it in the browser, or say why it cannot.
	 *
	 * Returns the minted value so a failure further along can revoke it: a
	 * persisted token nobody can reach is still a credential.
	 */
	async #issueRememberMe(user: UserPayload): Promise<string> {
		const strategy = strategyOrUndefined(this.#auth, this.#name);
		if (!strategy || !isRememberMeIssuer(strategy)) {
			throw new WardenError(
				"REMEMBER_ME_UNAVAILABLE",
				`Guard '${this.#name}' cannot keep a user signed in: no remember-me tokens are configured.`,
				{
					hint: "Set `rememberMeTokens` on the session guard, or call login(user) without the remember flag.",
				},
			);
		}
		const value = await strategy.issueRememberMeToken(user);
		if (value === null) {
			throw new WardenError(
				"REMEMBER_ME_UNAVAILABLE",
				`Guard '${this.#name}' cannot keep a user signed in: no remember-me tokens are configured.`,
				{
					hint: "Set `rememberMeTokens` on the session guard, or call login(user) without the remember flag.",
				},
			);
		}
		const write = this.#ctx.response.encryptedCookie;
		if (!write) {
			throw new WardenError(
				"REMEMBER_ME_UNAVAILABLE",
				"This host cannot write an encrypted cookie, which is where the remember-me token lives.",
				{
					hint: "Use a host whose response exposes encryptedCookie(), or call login(user) without the remember flag.",
				},
			);
		}
		try {
			write.call(this.#ctx.response, strategy.rememberMeCookieName, value, {
				maxAge: strategy.rememberMeAgeSeconds,
				httpOnly: true,
			});
		} catch (err) {
			// The row exists and the browser will never hold it: a credential
			// nobody can reach is still one, so it does not survive the failure.
			await strategy.revokeRememberMeToken(value).catch(() => undefined);
			throw err;
		}
		return value;
	}

	/** Drop whatever remember-me cookie the browser is still holding. */
	#clearRememberMe(): void {
		const strategy = strategyOrUndefined(this.#auth, this.#name);
		if (!strategy || !isRememberMeIssuer(strategy)) return;
		this.#ctx.response.clearCookie?.call(
			this.#ctx.response,
			strategy.rememberMeCookieName,
		);
	}

	/** Log the current user out of this guard (session guards). */
	logout(): Promise<void> {
		return this.#auth.logout(this.#requireSession(), this.#name, this.#state);
	}

	#requireSession(): SessionStore {
		if (!this.#ctx.session) {
			throw new WardenError(
				"NO_SESSION",
				`Guard '${this.#name}'.login()/logout() requires a session, but ctx.session is unset. Register the session middleware upstream.`,
			);
		}
		return this.#ctx.session;
	}
}

/**
 * Per-request Authenticator attached as `ctx.auth`. Mirrors AdonisJS's
 * `Authenticator` surface: `authenticate` / `check` / `authenticateUsing` /
 * `getUserOrFail` / `use`, plus the `user` / `isAuthenticated` /
 * `authenticationAttempted` / `authenticatedViaGuard` getters.
 */
export class Authenticator {
	readonly #ctx: WardenContext;
	readonly #auth: AuthManager;
	#user?: UserPayload;
	#viaGuard?: string;
	#attempted = false;
	readonly #guardCache = new Map<string, GuardAccessor>();

	constructor(ctx: WardenContext, auth: AuthManager) {
		this.#ctx = ctx;
		this.#auth = auth;
	}

	/** The authenticated user, or `undefined` for a guest. */
	get user(): UserPayload | undefined {
		return this.#user;
	}

	/** Whether the request has an authenticated user (AdonisJS name). */
	get isAuthenticated(): boolean {
		return this.#user !== undefined;
	}

	/** Whether `authenticate`/`check`/`authenticateUsing` ran this request. */
	get authenticationAttempted(): boolean {
		return this.#attempted;
	}

	/** Name of the guard that authenticated the request, if any. */
	get authenticatedViaGuard(): string | undefined {
		return this.#viaGuard;
	}

	/**
	 * Roles of the authenticated user (Ream reads `ctx.auth.roles ??
	 * ctx.auth.user.roles`). Warden nests them under `user`; this getter mirrors
	 * them at the top level for the host's guard readers.
	 */
	get roles(): string[] | undefined {
		return this.#user?.roles;
	}

	/** Permissions of the authenticated user (see {@link Authenticator.roles}). */
	get permissions(): string[] | undefined {
		return this.#user?.permissions;
	}

	/** Authenticate via the default guard. Throws `E_UNAUTHORIZED_ACCESS` on failure. */
	authenticate(): Promise<void> {
		return this.authenticateUsing([this.#auth.defaultStrategyName]);
	}

	/**
	 * Like {@link Authenticator.authenticate} but returns a boolean instead of
	 * throwing on a credential rejection. A strategy CRASH / config error still
	 * propagates (a server incident must not be silently swallowed as "guest").
	 */
	async check(): Promise<boolean> {
		try {
			await this.authenticate();
			return this.isAuthenticated;
		} catch (err) {
			if (err instanceof E_UNAUTHORIZED_ACCESS) return false;
			throw err;
		}
	}

	/**
	 * Try the given guards in order and report whether one succeeded, without
	 * throwing (AdonisJS `checkUsing`).
	 *
	 * The non-throwing sibling of {@link authenticateUsing}: `check()` is to
	 * `authenticate()` what this is to it. A handler that wants to branch on
	 * "is anyone signed in through either of these" had to wrap the throwing
	 * form in a try/catch itself.
	 */
	async checkUsing(
		guards?: string[],
		options?: { loginRoute?: string },
	): Promise<boolean> {
		try {
			await this.authenticateUsing(guards, options);
			return this.isAuthenticated;
		} catch (err) {
			// A credential rejection is an answer, not a failure. Anything else
			// — a crashed strategy, a config error — is still a real problem and
			// must not be reported as "not signed in".
			if (err instanceof E_UNAUTHORIZED_ACCESS) return false;
			throw err;
		}
	}

	/**
	 * Authenticate by trying the given guards in order (default: the default
	 * guard). Sets the user on the first success; throws `E_UNAUTHORIZED_ACCESS`
	 * (401, carrying `redirectTo` for session guards) when all reject, or a
	 * `WARDEN_AUTH_STRATEGY_ERROR` (500) when every attempted guard crashed.
	 */
	async authenticateUsing(
		guards?: string[],
		options?: { loginRoute?: string },
	): Promise<void> {
		this.#attempted = true;
		const names =
			guards && guards.length > 0 ? guards : [this.#auth.defaultStrategyName];
		const guardName = names[0] ?? this.#auth.defaultStrategyName;
		// Namespaced by the guard's driver, as AdonisJS does: `session_auth:*`,
		// `access_tokens_auth:*`, `basic_auth:*`. An app auditing session logins
		// must not be told about bearer-token traffic under the same name.
		this.#auth.emitAuthEvent(
			`${this.#auth.eventPrefixFor(guardName)}:authentication_attempted`,
			{ guardName },
		);
		const creds = extractCredentials(this.#ctx, this.#auth);
		// Same rule as the loop above: a session guard is one that verifies from
		// the request context. Matching the literal name meant a guard called
		// `web` never got the login redirect a browser needs.
		const hasSessionStrategy = names.some((name) =>
			isSessionGuard(this.#auth, name),
		);
		const attempt = await tryAuthenticate(this.#auth, names, creds);
		const { attemptCount, crashCount } = attempt;
		let result = attempt.result;
		let viaGuard = attempt.viaGuard;

		// No credential answered, but the browser may still hold a remember-me
		// cookie — that is what "keep me signed in" means, and nothing read it.
		if (!result?.authenticated && hasSessionStrategy) {
			for (const name of names) {
				const user = await this.use(name).tryRememberMeCookie();
				if (user) {
					result = { authenticated: true, user };
					viaGuard = name;
					break;
				}
			}
		}

		if (result?.authenticated && result.user) {
			this.#user = result.user;
			this.#viaGuard = viaGuard;
			// The guard that actually answered names the event, not the one asked
			// for first.
			const winner = viaGuard ?? guardName;
			this.#auth.emitAuthEvent(
				`${this.#auth.eventPrefixFor(winner)}:authentication_succeeded`,
				{ guardName: winner, user: result.user, sessionId: undefined },
			);
			return;
		}
		// Every attempted guard crashed → a server-side incident, not a
		// credential rejection. Surface distinctly (mapped to 500 by the caller).
		if (attemptCount > 0 && crashCount === attemptCount) {
			throw new WardenError(
				"AUTH_STRATEGY_ERROR",
				"Authentication unavailable — one or more strategies failed. Check server logs.",
				{ status: 500 },
			);
		}
		const failure = new E_UNAUTHORIZED_ACCESS(
			result?.error ?? "Unauthorized access",
			{
				guardDriverName: guardName,
				redirectTo: hasSessionStrategy ? options?.loginRoute : undefined,
			},
		);
		this.#auth.emitAuthEvent(
			`${this.#auth.eventPrefixFor(guardName)}:authentication_failed`,
			{ guardName, error: failure },
		);
		throw failure;
	}

	/** Return the authenticated user or throw `E_UNAUTHORIZED_ACCESS`. */
	getUserOrFail(): UserPayload {
		if (!this.#user) {
			throw new E_UNAUTHORIZED_ACCESS(
				'Cannot access authenticated user. Call "ctx.auth.authenticate()" first.',
				{ guardDriverName: this.#viaGuard ?? this.#auth.defaultStrategyName },
			);
		}
		return this.#user;
	}

	/** Access a named guard (AdonisJS `auth.use('web')`). Instances are cached per request. */
	use(name: string): GuardAccessor {
		let accessor = this.#guardCache.get(name);
		if (!accessor) {
			accessor = new GuardAccessor(this.#ctx, this.#auth, name, this);
			this.#guardCache.set(name, accessor);
		}
		return accessor;
	}

	/**
	 * @internal Seed the Authenticator from a result the enforcing middleware
	 * already computed, so `ctx.auth` reflects the authenticated user without a
	 * second verify pass.
	 */
	adopt(result: AuthResult | null, viaGuard: string | undefined): void {
		this.#attempted = true;
		if (result?.authenticated && result.user) {
			this.#user = result.user;
			this.#viaGuard = viaGuard;
		}
	}
}
