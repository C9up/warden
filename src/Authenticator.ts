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

import {
	type AuthManager,
	type AuthResult,
	type AuthStrategy,
	sanitizePayload,
	type UserPayload,
} from "./AuthManager.js";
import { E_UNAUTHORIZED_ACCESS, WardenError } from "./errors.js";
import type { WardenContext } from "./middleware.js";
import type { SessionStore } from "./strategies/SessionStrategy.js";

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
		hasSessionStrategy: boolean;
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
			if (strategyName === "session") {
				const strategy = auth.getStrategy(strategyName);
				const verifyWithContext =
					strategy && hasVerifyWithContext(strategy)
						? strategy.verifyWithContext
						: undefined;
				if (verifyWithContext) {
					attemptCount++;
					r = await verifyWithContext.call(strategy, "", { session });
					// The session path bypasses AuthManager.verify(), so apply the
					// same prototype-pollution guard JWT / api-key users get there.
					if (r.user) sanitizePayload(r.user);
				} else {
					continue;
				}
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

	/** Authenticate the request using only this guard (throws on failure). */
	authenticate(): Promise<void> {
		return this.#parent.authenticateUsing([this.#name]);
	}

	/** Log a user in through this guard (session guards). */
	login(user: UserPayload): Promise<void> {
		return this.#auth.login(user, this.#requireSession(), this.#name);
	}

	/** Log the current user out of this guard (session guards). */
	logout(): Promise<void> {
		return this.#auth.logout(this.#requireSession(), this.#name);
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
		// The four authentication events AdonisJS' session guard emits. An app
		// auditing logins subscribes to exactly these names.
		this.#auth.emitAuthEvent("session_auth:authentication_attempted", {
			guardName,
		});
		const creds = extractCredentials(this.#ctx, this.#auth);
		const hasSessionStrategy = names.includes("session");
		const { result, viaGuard, attemptCount, crashCount } =
			await tryAuthenticate(this.#auth, names, {
				...creds,
				hasSessionStrategy,
			});

		if (result?.authenticated && result.user) {
			this.#user = result.user;
			this.#viaGuard = viaGuard;
			this.#auth.emitAuthEvent("session_auth:authentication_succeeded", {
				guardName: viaGuard ?? guardName,
				user: result.user,
				sessionId: undefined,
			});
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
		this.#auth.emitAuthEvent("session_auth:authentication_failed", {
			guardName,
			error: failure,
		});
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
