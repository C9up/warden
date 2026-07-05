/**
 * API Key authentication strategy.
 *
 * Supports: Authorization: Bearer <key> or X-API-Key: <key>
 *
 * @implements MISS-8
 */

import type { AuthResult, AuthStrategy, UserPayload } from "../AuthManager.js";

export interface ApiKeyConfig {
	headerName?: string;
	findByKey: (
		key: string,
	) => Promise<{ user: UserPayload; scopes?: string[] } | null>;
}

export class ApiKeyStrategy implements AuthStrategy {
	// AdonisJS names this guard driver "access_tokens". The legacy "api-key"
	// spelling is still accepted as a guard name / credential trigger by the
	// middleware and providers (see `API_KEY_GUARD_NAMES`) for back-compat.
	name = "access_tokens";
	#config: ApiKeyConfig;
	#headerName: string;

	constructor(config: ApiKeyConfig) {
		this.#config = config;
		this.#headerName = config.headerName ?? "x-api-key";
	}

	/** The HTTP header name to extract the API key from. */
	get headerName(): string {
		return this.#headerName;
	}

	async authenticate(_credentials: {
		email: string;
		password: string;
	}): Promise<AuthResult> {
		throw new Error(
			"ApiKeyStrategy does not support credential-based auth. Use verify() with the API key.",
		);
	}

	async verify(token: string): Promise<AuthResult> {
		const result = await this.#config.findByKey(token);
		if (!result) return { authenticated: false, error: "Invalid API key" };

		const user: UserPayload = { ...result.user };
		if (result.scopes && result.scopes.length > 0) {
			// Expose the API key's scopes on `user.permissions` (without mutating
			// the source object) so APP code can read them via
			// `ctx.auth.user.permissions`.
			//
			// IMPORTANT — these scopes are a SEPARATE axis from the `@Permission`
			// route gate, by design (Adonis Bouncer parity): the gate flows through
			// RightsResolver, which resolves grants from the rights STORE and
			// deliberately ignores payload-carried permissions (see RightsResolver
			// D1). This mirrors AdonisJS, where token abilities are checked via
			// `currentAccessToken.allows(scope)` and are NOT consulted by Bouncer
			// ability/policy checks. So an API key carrying `orders.create` is NOT
			// auto-granted by `@Permission('orders.create')` — that's intentional,
			// not a bug. Gate API-key routes on scopes with an explicit app-level
			// check against `ctx.auth.user.permissions`.
			const merged = new Set([...(user.permissions ?? []), ...result.scopes]);
			user.permissions = [...merged];
		}
		return { authenticated: true, user };
	}
}
