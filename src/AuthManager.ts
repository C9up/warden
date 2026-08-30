/**
 * AuthManager — manages multiple authentication strategies.
 *
 * @implements FR48, FR50, FR51
 */

import { Authenticator } from "./Authenticator.js";
import { WardenError } from "./errors.js";
import type { WardenContext } from "./middleware.js";
import { sanitizePayload } from "./sanitize.js";

export { sanitizePayload };

import { MemoryRightsStore } from "./rights/MemoryRightsStore.js";
import { RightsResolver } from "./rights/RightsResolver.js";
import type { EffectivePermissions, Scope } from "./rights/types.js";
import type {
	SessionGuardState,
	SessionStore,
} from "./strategies/SessionStrategy.js";

export interface UserPayload {
	id: string;
	roles?: string[];
	permissions?: string[];
	[key: string]: unknown;
}

export interface AuthResult {
	authenticated: boolean;
	user?: UserPayload;
	error?: string;
	/**
	 * @internal Set when the strategy's `verify()` / `authenticate()` THREW
	 * a generic error (vs returned a deliberate `{ authenticated: false }`
	 * rejection). The middleware uses this to distinguish credential
	 * failures (→ 401) from strategy crashes (→ 500). Not part of the
	 * public consumer-facing API.
	 */
	strategyCrash?: true;
}

/**
 * What a test client must send to act as a user (AdonisJS `AuthClientResponse`).
 *
 * Each guard answers in its own currency — a header for a token guard, a
 * session entry for a session guard — so the test harness applies whichever
 * fields come back instead of knowing how each guard authenticates.
 */
export interface AuthClientResponse {
	/** Headers to set on the request. */
	headers?: Record<string, string>;
	/** Session values to seed before the request. */
	session?: Record<string, unknown>;
	/** Cookies to send. */
	cookies?: Record<string, string>;
}

/**
 * The event namespace for a guard, taken from its DRIVER.
 *
 * AdonisJS namespaces auth events per driver — `session_auth:*`,
 * `access_tokens_auth:*`, `basic_auth:*` — so an app can audit session logins
 * without also hearing about every bearer token. Warden emitted `session_auth:*`
 * whatever authenticated, which told a session listener about JWT traffic and
 * left no name to subscribe to for the others.
 *
 * Driven by the strategy's `name` rather than the guard's config key: a guard
 * called `web` running a `SessionStrategy` is still the session driver, exactly
 * as upstream. A driver already ending in `_auth` (`basic_auth`) keeps its name
 * rather than growing a second suffix, which is how AdonisJS spells it.
 */
export function authEventPrefix(driverName: string | undefined): string {
	if (!driverName) return "session_auth";
	return driverName.endsWith("_auth") ? driverName : `${driverName}_auth`;
}

export interface AuthStrategy {
	name: string;
	authenticate(credentials: Record<string, unknown>): Promise<AuthResult>;
	verify(token: string, context?: Record<string, unknown>): Promise<AuthResult>;
	/**
	 * Build what a test client sends to be this user (AdonisJS
	 * `authenticateAsClient`). Optional: a guard with no test seam simply has
	 * none, and the harness says so instead of forging one.
	 */
	authenticateAsClient?(
		...args: never[]
	): Promise<AuthClientResponse> | AuthClientResponse;
}

/**
 * AuthManager configuration. Two equivalent forms are accepted:
 *
 *   - AdonisJS form (preferred): `{ default, guards }` — `default` names the
 *     guard used when none is specified, `guards` maps guard name → strategy.
 *   - Legacy form: `{ defaultStrategy, strategies }` — kept working so existing
 *     call sites and tests need no change.
 *
 * Exactly one of each pair must be supplied. Internally normalised to the
 * AdonisJS names (`default` / `guards`).
 */
export interface AuthConfig {
	/** AdonisJS name for the default guard. */
	default?: string;
	/** AdonisJS name for the guard map (name → strategy). */
	guards?: Record<string, AuthStrategy>;
	/** Legacy alias for {@link AuthConfig.default}. */
	defaultStrategy?: string;
	/** Legacy alias for {@link AuthConfig.guards}. */
	strategies?: Record<string, AuthStrategy>;
	/**
	 * The rights resolver backing the coarse RBAC helpers (Epic 56). When
	 * absent, a default `RightsResolver(new MemoryRightsStore())` is used so
	 * `new AuthManager({ default, guards })` keeps working — with an empty
	 * store, payload roles still fold in (D2) and permissions are empty (token
	 * `user.permissions` is not an input — D1).
	 */
	rights?: RightsResolver;
}

/** A strategy that can mint a token for a resolved user (e.g. JwtStrategy). */
interface TokenIssuer {
	signToken(user: UserPayload): string;
}

/**
 * Capability check for {@link AuthManager.issueFor}. `signToken` is not on the
 * `AuthStrategy` interface (only token-minting strategies have it), so narrow
 * via `in` + `typeof` — no cast.
 */
function isTokenIssuer(
	strategy: AuthStrategy,
): strategy is AuthStrategy & TokenIssuer {
	return "signToken" in strategy && typeof strategy.signToken === "function";
}

/**
 * Manages authentication strategies and provides guard/permission checks.
 */
/**
 * The slice of an event emitter warden publishes through — `emit(name, data)`,
 * which is what both `@c9up/ream`'s Emitter and Adonis' expose.
 */
export interface WardenEmitter {
	emit(event: string, data: unknown): unknown;
}

export class AuthManager {
	// AdonisJS names: `guards` (name → strategy) and `default` (the guard used
	// when none is named). Renamed from the previous `strategies`/`defaultStrategy`.
	#guards: Map<string, AuthStrategy> = new Map();
	#default: string;
	readonly #rights: RightsResolver;

	/**
	 * Where auth events go. Structural and optional: warden is a leaf and must
	 * not import an emitter — a host wires its own through `setEmitter`, and one
	 * that wires none simply gets no events.
	 */
	#emitter: WardenEmitter | undefined;

	/**
	 * Publish auth events on `emitter`. AdonisJS emits six of them from its
	 * session guard, and an app that audits logins reads exactly those.
	 */
	setEmitter(emitter: WardenEmitter): this {
		this.#emitter = emitter;
		return this;
	}

	/**
	 * Publish one auth event. Public so the per-request `Authenticator` can
	 * report what it observed — it holds the guard chain, the manager holds the
	 * emitter.
	 */
	emitAuthEvent(event: string, payload: Record<string, unknown>): void {
		this.#emit(event, payload);
	}

	/** Fire-and-forget: an event listener must never break authentication. */
	#emit(event: string, payload: Record<string, unknown>): void {
		try {
			void this.#emitter?.emit(event, payload);
		} catch {
			// A throwing listener is the listener's problem, not the login's.
		}
	}

	constructor(config: AuthConfig) {
		// Normalise the two accepted forms — AdonisJS `{ default, guards }` and
		// the legacy `{ defaultStrategy, strategies }` — to the AdonisJS names.
		const guards = config.guards ?? config.strategies;
		const defaultGuard = config.default ?? config.defaultStrategy;
		if (!guards || defaultGuard === undefined) {
			throw new WardenError(
				"INVALID_CONFIG",
				"AuthManager: config must supply `default` + `guards` (or the legacy `defaultStrategy` + `strategies`).",
			);
		}
		this.#default = defaultGuard;
		this.#rights = config.rights ?? new RightsResolver(new MemoryRightsStore());
		for (const [name, strategy] of Object.entries(guards)) {
			this.#guards.set(name, strategy);
		}
		// Fail-fast at construction: an AuthManager with zero guards is a
		// configuration bug. Previously, an empty `guards: {}` passed the
		// constructor cleanly and the first protected request crashed at
		// runtime when `getStrategy('jwt')` threw — opaque 401 or 500 instead
		// of a boot-time INVALID_CONFIG that points the operator at the missing
		// `config.auth.jwt` (or other guard).
		if (this.#guards.size === 0) {
			throw new WardenError(
				"INVALID_CONFIG",
				`AuthManager: no authentication guards registered. Configure at least one guard (e.g. config.warden.auth.jwt) before booting WardenProvider.`,
			);
		}
		if (!this.#guards.has(defaultGuard)) {
			throw new WardenError(
				"INVALID_CONFIG",
				`default guard '${defaultGuard}' is not present in guards`,
			);
		}
	}

	/** Authenticate with credentials using a specific or default strategy. */
	async authenticate(
		credentials: Record<string, unknown>,
		strategyName?: string,
	): Promise<AuthResult> {
		const strategy = this.getStrategy(strategyName);
		try {
			const result = await strategy.authenticate(credentials);
			if (result.user) sanitizePayload(result.user);
			return result;
		} catch (err) {
			// Re-throw structured WardenError sentinels (e.g. SessionStrategy's
			// USE_LOGIN throw) so callers see the design-boundary signal instead
			// of a soft `{ authenticated: false }`. Generic errors stay soft.
			if (err instanceof WardenError) throw err;
			return {
				authenticated: false,
				error:
					err instanceof Error ? err.message : "Unknown authentication error",
			};
		}
	}

	/** Verify a token (JWT, session, API key). */
	async verify(
		token: string,
		strategyName?: string,
		context?: Record<string, unknown>,
	): Promise<AuthResult> {
		const strategy = this.getStrategy(strategyName);
		try {
			const result = await strategy.verify(token, context);
			if (result.user) sanitizePayload(result.user);
			return result;
		} catch (err) {
			// Mirror authenticate(): rethrow structured WardenError sentinels;
			// soft-fail generic throws but TAG them as strategy crashes so the
			// middleware can flip 401 → 500 when every attempted strategy bombed.
			if (err instanceof WardenError) throw err;
			return {
				authenticated: false,
				error:
					err instanceof Error ? err.message : "Unknown verification error",
				strategyCrash: true,
			};
		}
	}

	/**
	 * Mint a token for an ALREADY-resolved user — the "login-as-known-user"
	 * path (e.g. straight after signup created the row in the app's own
	 * transaction). Skips the credential check `authenticate()` performs, so no
	 * redundant bcrypt / DB lookup, and the app never has to reach into the
	 * strategy internals.
	 *
	 * The token is byte-for-byte what `authenticate()` would emit for the same
	 * `user` (it delegates to the same `signToken`), so the claims — sub / roles
	 * / permissions / iat / exp / jti — are identical. Throws if the resolved
	 * strategy can't issue tokens (e.g. session / API-key strategies).
	 */
	issueFor(user: UserPayload, strategyName?: string): string {
		const strategy = this.getStrategy(strategyName);
		if (!isTokenIssuer(strategy)) {
			throw new WardenError(
				"STRATEGY_CANNOT_ISSUE",
				`Auth strategy '${strategyName ?? this.#default}' cannot issue tokens.`,
				{
					hint: "issueFor() needs a token-minting strategy (e.g. JwtStrategy with signToken). Session / API-key strategies don't mint tokens.",
				},
			);
		}
		return strategy.signToken(user);
	}

	/**
	 * Resolve a user's effective permissions for a scope (Epic 56). The single
	 * resolution entry the coarse helpers wrap — `hasRole`/`hasPermission`/
	 * `hasAllPermissions` read this set, never the token payload directly. The
	 * Bouncer policy path (`this.permissions`, 56.3) consults the SAME resolver,
	 * so a coarse question and a policy question return the same answer for the
	 * same `(user, scope)` (the single unification point — AC-E3).
	 */
	resolvePermissions(
		user: UserPayload,
		scope: Scope = "global",
	): Promise<EffectivePermissions> {
		return this.#rights.resolve(user, scope);
	}

	/**
	 * Check if a user has a specific role within a scope (default `"global"`).
	 * Reflects payload roles ∪ store roles (D2) — a token-carried role still
	 * satisfies it with no store config.
	 */
	async hasRole(
		user: UserPayload,
		role: string,
		scope: Scope = "global",
	): Promise<boolean> {
		return (await this.resolvePermissions(user, scope)).roles.has(role);
	}

	/**
	 * Check if a user has a specific permission within a scope (default
	 * `"global"`). Derived from roles + store grants ONLY — token
	 * `user.permissions` is NOT read (D1, cerebrum 459).
	 */
	async hasPermission(
		user: UserPayload,
		permission: string,
		scope: Scope = "global",
	): Promise<boolean> {
		return (await this.resolvePermissions(user, scope)).has(permission);
	}

	/**
	 * Check if a user has ALL required permissions within a scope (default
	 * `"global"`). Empty list ⇒ vacuously true.
	 */
	async hasAllPermissions(
		user: UserPayload,
		permissions: string[],
		scope: Scope = "global",
	): Promise<boolean> {
		return (await this.resolvePermissions(user, scope)).hasAll(permissions);
	}

	/** Get a registered strategy by name. */
	/**
	 * An {@link Authenticator} bound to one request (AdonisJS
	 * `createAuthenticator`).
	 *
	 * What the HTTP middleware builds per request. Exposed so anything outside
	 * that path — a console command acting as a user, a background job — can
	 * build one without reaching for the class.
	 */
	createAuthenticator(ctx: WardenContext): Authenticator {
		return new Authenticator(ctx, this);
	}

	/**
	 * What a test client needs to authenticate as a user (AdonisJS
	 * `createAuthenticatorClient`).
	 *
	 * Delegates to the guard's own `authenticateAsClient`, so a guard with no
	 * test seam says so instead of having one forged for it.
	 */
	createAuthenticatorClient(): {
		use(guard?: string): {
			authenticateAsClient(
				...args: never[]
			): Promise<AuthClientResponse> | AuthClientResponse;
		};
	} {
		return {
			use: (guard?: string) => {
				const strategy = this.getStrategy(guard);
				const seam = strategy.authenticateAsClient?.bind(strategy);
				if (!seam) {
					throw new WardenError(
						"STRATEGY_HAS_NO_CLIENT",
						`Auth strategy '${guard ?? this.#default}' has no authenticateAsClient() — it cannot forge a client request.`,
						{
							hint: "Implement authenticateAsClient() on the strategy, or authenticate through a real login in the test.",
						},
					);
				}
				return { authenticateAsClient: seam };
			},
		};
	}

	/**
	 * The event namespace a guard's events carry, resolved from its driver.
	 * Falls back to `session_auth` when the guard cannot be resolved, so a
	 * failure to look one up never becomes a second failure at emit time.
	 */
	eventPrefixFor(guardName?: string): string {
		try {
			return authEventPrefix(this.getStrategy(guardName).name);
		} catch {
			return authEventPrefix(undefined);
		}
	}

	getStrategy(name?: string): AuthStrategy {
		const strategyName = name ?? this.#default;
		const strategy = this.#guards.get(strategyName);
		if (!strategy) {
			throw new WardenError(
				"STRATEGY_NOT_FOUND",
				`Auth strategy '${strategyName}' not registered`,
				{
					hint: "Call registerStrategy() before using this strategy name.",
				},
			);
		}
		return strategy;
	}

	/**
	 * Name of the default guard (Adonis's "default guard"). Used by `silentAuth`
	 * and the {@link Authenticator} to pick which guard to attempt when a route
	 * declares none.
	 */
	get defaultStrategyName(): string {
		return this.#default;
	}

	/** Register a new strategy at runtime. */
	registerStrategy(name: string, strategy: AuthStrategy): void {
		this.#guards.set(name, strategy);
	}

	/** Get all registered strategy names. */
	getStrategyNames(): string[] {
		return [...this.#guards.keys()];
	}

	/**
	 * Log a user in through a session-capable guard (AdonisJS
	 * `auth.use('web').login(user)` parity). Delegates to the guard's own
	 * `login()` — for `SessionStrategy` this rotates the session id (session
	 * fixation defence) and stores the user id. Throws if the resolved guard
	 * cannot log in (e.g. JWT / API-key guards, which are stateless).
	 *
	 * Fixes the misleading `SessionStrategy.authenticate()` sentinel that
	 * pointed at a then-nonexistent `authManager.login()` (bug-3261).
	 */
	async login(
		user: UserPayload,
		session: SessionStore,
		strategyName?: string,
		state?: SessionGuardState,
	): Promise<void> {
		const strategy = this.getStrategy(strategyName);
		if (!isLoginCapable(strategy)) {
			throw new WardenError(
				"STRATEGY_CANNOT_LOGIN",
				`Auth strategy '${strategyName ?? this.#default}' does not support session login.`,
				{
					hint: "login()/logout() need a stateful guard (e.g. SessionStrategy). JWT / API-key guards are stateless — mint a token with issueFor() instead.",
				},
			);
		}
		const prefix = authEventPrefix(strategy.name);
		this.#emit(`${prefix}:login_attempted`, {
			guardName: strategyName ?? this.#default,
			user,
		});
		await strategy.login(user, session, state);
		this.#emit(`${prefix}:login_succeeded`, {
			guardName: strategyName ?? this.#default,
			user,
			sessionId: undefined,
		});
	}

	/**
	 * Revive a user from a remember-me cookie through a session guard, recording
	 * the attempt on the caller's per-request `state`.
	 *
	 * The returned `cookieValue` must replace the one the browser holds — the
	 * token is single-use and recycled on every successful revival.
	 */
	async authenticateViaRememberMeToken(
		cookieValue: unknown,
		strategyName?: string,
		state?: SessionGuardState,
	): Promise<{ user: UserPayload; cookieValue: string } | null> {
		const strategy = this.getStrategy(strategyName);
		if (!isRememberMeCapable(strategy)) {
			throw new WardenError(
				"STRATEGY_CANNOT_LOGIN",
				`Auth strategy '${strategyName ?? this.#default}' has no remember-me tokens.`,
				{
					hint: "Remember-me is a session-guard feature. Configure `rememberMeTokens` on the guard, or implement authenticateViaRememberMeToken() on your own.",
				},
			);
		}
		return strategy.authenticateViaRememberMeToken(cookieValue, state);
	}

	/**
	 * Log a user out of a session-capable guard (AdonisJS `auth.use('web').logout()`
	 * parity). Delegates to the guard's `logout()`. Throws if the resolved guard
	 * cannot log out.
	 */
	async logout(
		session: SessionStore,
		strategyName?: string,
		state?: SessionGuardState,
	): Promise<void> {
		const strategy = this.getStrategy(strategyName);
		if (!isLoginCapable(strategy)) {
			throw new WardenError(
				"STRATEGY_CANNOT_LOGIN",
				`Auth strategy '${strategyName ?? this.#default}' does not support session logout.`,
			);
		}
		await strategy.logout(session, state);
		this.#emit(`${authEventPrefix(strategy.name)}:logged_out`, {
			guardName: strategyName ?? this.#default,
			user: null,
			error: null,
		});
	}
}

/** A guard that can start/stop a session for a resolved user (e.g. SessionStrategy). */
/** A guard that can revive a user from a remember-me cookie. */
interface RememberMeCapable {
	authenticateViaRememberMeToken(
		cookieValue: unknown,
		state?: SessionGuardState,
	): Promise<{ user: UserPayload; cookieValue: string } | null>;
}

/**
 * Capability check for {@link AuthManager.authenticateViaRememberMeToken}.
 *
 * Structural, like {@link isLoginCapable} beside it, and NOT an `instanceof`:
 * a guard an application wrote itself, carrying the same method, is as capable
 * as the one shipped here — refusing it would make the built-in strategy the
 * only one that can ever hold a remember-me token.
 */
function isRememberMeCapable(
	strategy: AuthStrategy,
): strategy is AuthStrategy & RememberMeCapable {
	return (
		"authenticateViaRememberMeToken" in strategy &&
		typeof strategy.authenticateViaRememberMeToken === "function"
	);
}

interface LoginCapable {
	login(
		user: UserPayload,
		session: SessionStore,
		state?: SessionGuardState,
	): Promise<void>;
	logout(session: SessionStore, state?: SessionGuardState): Promise<void>;
}

/**
 * Capability check for {@link AuthManager.login}/{@link AuthManager.logout}.
 * `login`/`logout` are not on the base `AuthStrategy` contract (only stateful
 * guards implement them), so narrow via `in` + `typeof` — no cast.
 */
function isLoginCapable(
	strategy: AuthStrategy,
): strategy is AuthStrategy & LoginCapable {
	return (
		"login" in strategy &&
		typeof strategy.login === "function" &&
		"logout" in strategy &&
		typeof strategy.logout === "function"
	);
}

/** Strip dangerous prototype-pollution keys from user payload. */
/**
 * Strip prototype-pollution keys from a user payload before it's
 * attached to the request. Exported so the middleware can apply it to
 * the session path too — session auth goes through `verifyWithContext`
 * directly (not `AuthManager.verify`), so without this it would skip
 * the guard JWT / api-key users get.
 */
