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

import type { AuthStrategy, UserPayload } from "./AuthManager.js";
import type { BasePolicy } from "./bouncer/BasePolicy.js";
import type { Ability } from "./bouncer/types.js";
import { DiscordDriver } from "./firstcontact/drivers/DiscordDriver.js";
import { FacebookDriver } from "./firstcontact/drivers/FacebookDriver.js";
import { GitHubDriver } from "./firstcontact/drivers/GitHubDriver.js";
import { GoogleDriver } from "./firstcontact/drivers/GoogleDriver.js";
import { LinkedInDriver } from "./firstcontact/drivers/LinkedInDriver.js";
import { LinkedInOpenidConnectDriver } from "./firstcontact/drivers/LinkedInOpenidConnectDriver.js";
import { SpotifyDriver } from "./firstcontact/drivers/SpotifyDriver.js";
import { TwitterDriver } from "./firstcontact/drivers/TwitterDriver.js";
import type { FirstContactDriver, OAuthConfig } from "./firstcontact/types.js";
import type { MfaManager } from "./mfa/MfaManager.js";
import type { RightsStore, Scope } from "./rights/types.js";
import type { ApiKeyConfig } from "./strategies/ApiKeyStrategy.js";
import { ApiKeyStrategy } from "./strategies/ApiKeyStrategy.js";
import {
	type BasicAuthConfig,
	BasicAuthStrategy,
} from "./strategies/BasicAuthStrategy.js";
import { JwtStrategy } from "./strategies/JwtStrategy.js";
import type { SessionStrategyConfig } from "./strategies/SessionStrategy.js";
import { SessionStrategy } from "./strategies/SessionStrategy.js";
import type { TokenBlacklist } from "./TokenBlacklist.js";

/**
 * Minimal request shape passed to `resolveScope` — enough to derive a tenant
 * from a header or the authenticated user, without coupling config to the full
 * HTTP context type (keeps Warden agnostic of the host framework).
 */
export interface ScopeRequestContext {
	request: { headers: Record<string, string> };
	auth?: { user?: UserPayload | null };
}

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

/**
 * A guard entry in the AdonisJS-style config — an {@link AuthStrategy} instance,
 * built via {@link jwtGuard}/{@link sessionGuard}/{@link apiKeyGuard}. Named a
 * "factory" for AdonisJS symmetry (`sessionGuard({...})`), though Warden guards
 * are shared per-app instances (the per-request state lives on the Authenticator).
 */
export type GuardFactory = AuthStrategy;

/** Build a JWT guard from its config (AdonisJS `jwtGuard()` shape). */
export function jwtGuard(config: JwtConfig): GuardFactory {
	return new JwtStrategy(config);
}

/** Build a session guard from its config (AdonisJS `sessionGuard()` shape). */
export function sessionGuard(config: SessionStrategyConfig): GuardFactory {
	return new SessionStrategy(config);
}

/** Build an API-key / access-tokens guard from its config. */
export function apiKeyGuard(config: ApiKeyConfig): GuardFactory {
	return new ApiKeyStrategy(config);
}

/** Build an HTTP Basic guard from its config (AdonisJS `basicAuthGuard()`). */
export function basicAuthGuard(config: BasicAuthConfig): GuardFactory {
	return new BasicAuthStrategy(config);
}

/** A social sign-in driver, built when the provider registers. */
export type SocialDriverFactory = () => FirstContactDriver;

/**
 * The social sign-in providers a config file names.
 *
 *   socials: {
 *     google: socials.google({ clientId, clientSecret, callbackUrl }),
 *   }
 *
 * The key is YOURS: two entries may use the same driver with different
 * credentials, and `firstContact.use(name)` asks for the key, not the driver.
 *
 * Factories are lazy, so a config that names a provider the environment never
 * selects costs nothing to declare.
 */
export const socials = {
	discord(config: OAuthConfig): SocialDriverFactory {
		return () => new DiscordDriver(config);
	},
	facebook(config: OAuthConfig): SocialDriverFactory {
		return () => new FacebookDriver(config);
	},
	github(config: OAuthConfig): SocialDriverFactory {
		return () => new GitHubDriver(config);
	},
	google(config: OAuthConfig): SocialDriverFactory {
		return () => new GoogleDriver(config);
	},
	/**
	 * LinkedIn through the member API, for an application whose LinkedIn app
	 * holds `r_liteprofile` / `r_emailaddress`.
	 */
	linkedin(config: OAuthConfig): SocialDriverFactory {
		return () => new LinkedInDriver(config);
	},
	/** LinkedIn through OpenID Connect — what a new application is issued. */
	linkedinOpenidConnect(config: OAuthConfig): SocialDriverFactory {
		return () => new LinkedInOpenidConnectDriver(config);
	},
	spotify(config: OAuthConfig): SocialDriverFactory {
		return () => new SpotifyDriver(config);
	},
	/** X requires PKCE — see `createCodeVerifier()`. */
	twitter(config: OAuthConfig): SocialDriverFactory {
		return () => new TwitterDriver(config);
	},
};

export interface WardenConfig {
	/**
	 * AdonisJS-style default guard NAME — the key in {@link WardenConfig.guards}
	 * used when a route/call names none. Preferred over {@link
	 * WardenConfig.defaultStrategy}.
	 */
	default?: string;
	/**
	 * AdonisJS-style named guard map, e.g.
	 * `{ web: sessionGuard({...}), api: jwtGuard({...}) }`. Guards are named by
	 * YOU (multiple instances of the same driver are allowed). When supplied,
	 * this takes precedence over the driver-keyed `jwt`/`session`/`apiKey` fields.
	 */
	guards?: Record<string, GuardFactory>;
	/**
	 * Login route an HTML client is redirected to when a session-guarded request
	 * is unauthenticated (AdonisJS session renderer parity). Absent ⇒ 401 JSON.
	 */
	loginRoute?: string;
	/** Legacy default auth strategy name (default: 'jwt'). Prefer {@link WardenConfig.default}. */
	defaultStrategy?: string;
	/** JWT strategy configuration (legacy driver-keyed form). */
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
	 * Standalone abilities the per-request Bouncer knows by name (Epic 56.6).
	 * Keyed by the string passed to `ctx.bouncer.authorize('post.edit', …)`.
	 * Define with `Bouncer.ability((user, post) => …)`.
	 */
	abilities?: Record<string, Ability<never[]>>;
	/**
	 * Class-based policies the per-request Bouncer knows by name (Epic 56.6).
	 * Reachable via `ctx.bouncer.with('PostPolicy')`. Each entry is the policy
	 * constructor; a fresh instance is created per check.
	 */
	policies?: Record<string, new () => BasePolicy>;
	/**
	 * Derive the authorization scope for a request (AD4 — scope-first). Return
	 * `{ tenant }` to scope rights to a tenant (e.g. from a subdomain or header),
	 * or `"global"`. Omitted ⇒ every request runs in the implicit `global` scope
	 * (zero config for single-tenant apps).
	 */
	resolveScope?: (ctx: ScopeRequestContext) => Scope | Promise<Scope>;
	/**
	 * Multi-factor authentication. Supply a configured `MfaManager` (built with
	 * your persistent stores + providers) to register it in the container as
	 * `MfaManager` / `"mfa"`. Required to use `@RequireMfa` step-up flows.
	 */
	mfa?: { manager: MfaManager };
	/**
	 * Social sign-in providers, keyed by the name `firstContact.use(name)` asks
	 * for. Build the entries with the {@link socials} helpers, or pass a driver
	 * of your own.
	 *
	 * Declared here, the manager is built and registered in the container as
	 * `FirstContactManager` / `"socials"`. Without this section there is no
	 * manager to resolve — which is what an application had to assemble by hand
	 * before.
	 */
	socials?: Record<string, FirstContactDriver | SocialDriverFactory>;
}

/** Typed config helper — identity function for editor inference. */
export function defineConfig(config: WardenConfig): WardenConfig {
	return config;
}
