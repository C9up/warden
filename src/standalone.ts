/**
 * Standalone Warden factory — works without the Ream IoC container.
 *
 * Same pattern as `createBlackhole()`: construct the auth manager from a
 * config object, return a typed handle that Express/Fastify/Hono can use.
 *
 * @example Express
 *   import { createWarden } from '@c9up/warden/standalone'
 *   const warden = createWarden({
 *     defaultStrategy: 'jwt',
 *     jwt: { secret: '...', findUser: ..., verifyCredentials: ... },
 *   })
 *   app.use(warden.expressMiddleware())
 *
 * @example Manual
 *   const result = await warden.verify(token)
 *   if (!result.authenticated) return res.status(401).json(result)
 */

import {
	AuthManager,
	type AuthResult,
	type AuthStrategy,
	type UserPayload,
} from "./AuthManager.js";
import { readBearerToken } from "./bearer.js";
import type { WardenConfig } from "./config.js";
import { ApiKeyStrategy } from "./strategies/ApiKeyStrategy.js";
import { JwtStrategy } from "./strategies/JwtStrategy.js";
import { SessionStrategy } from "./strategies/SessionStrategy.js";

/**
 * The slice of an Express-style request the middleware reads and writes.
 * Structural, so an Express, Connect or Polka request fits without a cast.
 */
export interface StandaloneRequest {
	headers?: Record<string, string | string[] | undefined>;
	/** The verification result, set on success. */
	auth?: AuthResult;
	/** The authenticated user, set on success (Express convention). */
	user?: UserPayload;
}

/** The slice of an Express-style response the middleware writes to. */
export interface StandaloneResponse {
	status(code: number): { json(body: unknown): unknown };
}

export interface Warden {
	/** Verify a bearer token. Returns auth result with user payload. */
	verify(token: string, strategy?: string): Promise<AuthResult>;
	/** Authenticate with credentials (email + password). */
	authenticate(
		credentials: Record<string, unknown>,
		strategy?: string,
	): Promise<AuthResult>;
	/**
	 * Mint a token for a user through a token-issuing guard: the one named, or
	 * the default guard. Rejects with `E_WARDEN_STRATEGY_CANNOT_ISSUE` when that
	 * guard mints no tokens (a session guard, an access-tokens guard).
	 */
	generateToken(user: UserPayload, guard?: string): Promise<string>;
	/** The underlying AuthManager for advanced use. */
	manager: AuthManager;
	/** Express middleware — extracts Bearer token, verifies, attaches `req.auth`. */
	expressMiddleware(): (
		req: StandaloneRequest,
		res: StandaloneResponse,
		next: () => void,
	) => void;
}

/** Send one JSON error, shaped like the Ream middleware's. */
function fail(
	res: StandaloneResponse,
	status: number,
	code: string,
	message: string,
): void {
	res.status(status).json({ error: { code, message } });
}

/**
 * Create a standalone Warden instance — no Ream container needed.
 */
export function createWarden(config: WardenConfig): Warden {
	// Mirror WardenProvider: accept the AdonisJS `guards` form OR the legacy
	// driver-keyed fields, building EVERY configured strategy — otherwise
	// config.session / config.apiKey were silently dropped and a jwt-less config
	// (e.g. { defaultStrategy: 'api-key', apiKey }) threw INVALID_CONFIG at boot
	// (audit 2026-06-13). Keys match the @Guard names.
	const strategies: Record<string, AuthStrategy> = {};

	if (config.guards && Object.keys(config.guards).length > 0) {
		Object.assign(strategies, config.guards);
	} else {
		if (config.jwt) {
			strategies.jwt = new JwtStrategy(config.jwt);
		}
		if (config.session) {
			strategies.session = new SessionStrategy(config.session);
		}
		if (config.apiKey) {
			const apiKey = new ApiKeyStrategy(config.apiKey);
			strategies.access_tokens = apiKey;
			strategies["api-key"] = apiKey;
		}
	}

	const manager = new AuthManager({
		default:
			config.default ?? config.defaultStrategy ?? Object.keys(strategies)[0],
		guards: strategies,
	});

	return {
		verify: (token, strategy) => manager.verify(token, strategy),
		authenticate: (credentials, strategy) =>
			manager.authenticate(credentials, strategy),

		async generateToken(user: UserPayload, guard?: string): Promise<string> {
			// The guard the application configured, not one named `jwt`: a
			// `guards: { api: jwtGuard(...) }` config has no guard by that name.
			return manager.issueFor(user, guard);
		},

		manager,

		expressMiddleware() {
			return (req, res, next) => {
				const token = readBearerToken(req.headers?.authorization);

				if (!token) {
					fail(
						res,
						401,
						"E_WARDEN_UNAUTHORIZED",
						"Missing authentication token",
					);
					return;
				}

				manager
					.verify(token)
					.then((result) => {
						if (result.strategyCrash === true) {
							// The guard threw — a database down, a bug — which is a
							// server incident, not a bad credential: a 500, and a
							// generic message. The thrown text (a host, a port, a
							// query) is for the logs, never for the client.
							console.error(
								`[warden] strategy threw during verify(): ${result.error ?? "unknown error"}`,
							);
							fail(
								res,
								500,
								"E_WARDEN_AUTH_STRATEGY_ERROR",
								"Authentication unavailable. Check server logs.",
							);
							return;
						}
						if (!result.authenticated || !result.user) {
							fail(
								res,
								401,
								"E_WARDEN_UNAUTHORIZED",
								result.error ?? "Authentication failed",
							);
							return;
						}
						// Attach auth result to the request object (Express convention).
						req.auth = result;
						req.user = result.user;
						next();
					})
					.catch(() => {
						fail(
							res,
							500,
							"E_WARDEN_AUTH_ERROR",
							"Internal authentication error",
						);
					});
			};
		},
	};
}
