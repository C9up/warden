/**
 * AuthManager — manages multiple authentication strategies.
 *
 * @implements FR48, FR50, FR51
 */

import { WardenError } from "./errors.js";
import { MemoryRightsStore } from "./rights/MemoryRightsStore.js";
import { RightsResolver } from "./rights/RightsResolver.js";
import type { EffectivePermissions, Scope } from "./rights/types.js";

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

export interface AuthStrategy {
	name: string;
	authenticate(credentials: Record<string, unknown>): Promise<AuthResult>;
	verify(token: string, context?: Record<string, unknown>): Promise<AuthResult>;
}

export interface AuthConfig {
	defaultStrategy: string;
	strategies: Record<string, AuthStrategy>;
	/**
	 * The rights resolver backing the coarse RBAC helpers (Epic 56). When
	 * absent, a default `RightsResolver(new MemoryRightsStore())` is used so
	 * `new AuthManager({ defaultStrategy, strategies })` keeps working — with
	 * an empty store, payload roles still fold in (D2) and permissions are
	 * empty (token `user.permissions` is not an input — D1).
	 */
	rights?: RightsResolver;
}

/**
 * Manages authentication strategies and provides guard/permission checks.
 */
export class AuthManager {
	private strategies: Map<string, AuthStrategy> = new Map();
	private defaultStrategy: string;
	private readonly rights: RightsResolver;

	constructor(config: AuthConfig) {
		this.defaultStrategy = config.defaultStrategy;
		this.rights = config.rights ?? new RightsResolver(new MemoryRightsStore());
		for (const [name, strategy] of Object.entries(config.strategies)) {
			this.strategies.set(name, strategy);
		}
		// Fail-fast at construction: an AuthManager with zero strategies
		// is a configuration bug. Previously, an empty `strategies: {}`
		// passed the constructor cleanly and the first protected request
		// crashed at runtime when `getStrategy('jwt')` threw — opaque 401
		// or 500 instead of a boot-time INVALID_CONFIG that points the
		// operator at the missing `config.auth.jwt` (or other strategy).
		if (Object.keys(config.strategies).length === 0) {
			throw new WardenError(
				"INVALID_CONFIG",
				`AuthManager: no authentication strategies registered. Configure at least one strategy (e.g. config.warden.auth.jwt) before booting WardenProvider.`,
			);
		}
		if (!this.strategies.has(config.defaultStrategy)) {
			throw new WardenError(
				"INVALID_CONFIG",
				`defaultStrategy '${config.defaultStrategy}' is not present in strategies`,
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
		return this.rights.resolve(user, scope);
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
	getStrategy(name?: string): AuthStrategy {
		const strategyName = name ?? this.defaultStrategy;
		const strategy = this.strategies.get(strategyName);
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

	/** Register a new strategy at runtime. */
	registerStrategy(name: string, strategy: AuthStrategy): void {
		this.strategies.set(name, strategy);
	}

	/** Get all registered strategy names. */
	getStrategyNames(): string[] {
		return [...this.strategies.keys()];
	}
}

/** Strip dangerous prototype-pollution keys from user payload. */
/**
 * Strip prototype-pollution keys from a user payload before it's
 * attached to the request. Exported so the middleware can apply it to
 * the session path too — session auth goes through `verifyWithContext`
 * directly (not `AuthManager.verify`), so without this it would skip
 * the guard JWT / api-key users get.
 */
export function sanitizePayload(user: UserPayload): void {
	for (const key of ["__proto__", "constructor", "prototype"]) {
		if (key in user) {
			delete (user as Record<string, unknown>)[key];
		}
	}
}
