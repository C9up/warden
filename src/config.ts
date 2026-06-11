/**
 * Warden configuration — declared in `config/auth.ts` of the user app.
 *
 * @example
 *   // config/auth.ts
 *   import { defineConfig } from '@c9up/warden/config'
 *   export default defineConfig({
 *     defaultStrategy: 'jwt',
 *     jwt: {
 *       secret: env('APP_KEY'),
 *       expiresInSeconds: 3600,
 *       findUser: (id) => User.find(id),
 *       verifyCredentials: (email, password) => User.verifyCredentials(email, password),
 *     },
 *   })
 */

import type { UserPayload } from "./AuthManager.js";
import type { MfaManager } from "./mfa/MfaManager.js";
import type { RightsStore } from "./rights/types.js";
import type { ApiKeyConfig } from "./strategies/ApiKeyStrategy.js";
import type { SessionStrategyConfig } from "./strategies/SessionStrategy.js";
import type { TokenBlacklist } from "./TokenBlacklist.js";

export interface JwtConfig {
	secret: string;
	expiresInSeconds?: number;
	findUser: (id: string) => Promise<UserPayload | null>;
	verifyCredentials: (
		email: string,
		password: string,
	) => Promise<UserPayload | null>;
	/**
	 * Optional revocation list. Supply a `TokenBlacklist` (Memory/Redis-backed) to
	 * enable `revoke()`/early-rejection of JWTs before expiry. Without it, `revoke()`
	 * throws (the call would be a silent no-op).
	 */
	blacklist?: TokenBlacklist;
}

export interface WardenConfig {
	/** Default auth strategy (default: 'jwt'). */
	defaultStrategy?: string;
	/** JWT strategy configuration. */
	jwt?: JwtConfig;
	/**
	 * Session strategy configuration. Supply `findUser` so `@Guard('session')`
	 * routes resolve the authenticated user from the session id. Without this,
	 * the `session` strategy is unregistered and `@Guard('session')` throws.
	 */
	session?: SessionStrategyConfig;
	/**
	 * API-key strategy configuration. Supply `findByKey` so `@Guard('api-key')`
	 * routes resolve the user (and scopes) from the request header. Without this,
	 * the `api-key` strategy is unregistered and `@Guard('api-key')` throws.
	 */
	apiKey?: ApiKeyConfig;
	/**
	 * Rights layer configuration (Epic 56). Supply a custom `store` to back the
	 * unified resolver with a DB-backed driver; when omitted, an in-memory
	 * `MemoryRightsStore` is registered as the default (AD5 — pluggable store,
	 * in-memory shipped).
	 */
	rights?: { store?: RightsStore };
	/**
	 * Multi-factor authentication. Supply a configured `MfaManager` (built with
	 * your persistent stores + providers) to register it in the container as
	 * `MfaManager` / `"mfa"`. Required to use `@RequireMfa` step-up flows.
	 */
	mfa?: { manager: MfaManager };
}

/** Typed config helper — identity function for editor inference. */
export function defineConfig(config: WardenConfig): WardenConfig {
	return config;
}
