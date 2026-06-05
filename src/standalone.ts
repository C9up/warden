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
	type UserPayload,
} from "./AuthManager.js";
import type { WardenConfig } from "./config.js";
import { JwtStrategy } from "./strategies/JwtStrategy.js";

export interface Warden {
	/** Verify a bearer token. Returns auth result with user payload. */
	verify(token: string, strategy?: string): Promise<AuthResult>;
	/** Authenticate with credentials (email + password). */
	authenticate(
		credentials: Record<string, unknown>,
		strategy?: string,
	): Promise<AuthResult>;
	/** Generate a JWT for a user (jwt strategy only). */
	generateToken(user: UserPayload): Promise<string>;
	/** The underlying AuthManager for advanced use. */
	manager: AuthManager;
	/** Express middleware — extracts Bearer token, verifies, attaches `req.auth`. */
	expressMiddleware(): (
		req: Record<string, unknown>,
		res: Record<string, unknown>,
		next: () => void,
	) => void;
}

/**
 * Create a standalone Warden instance — no Ream container needed.
 */
export function createWarden(config: WardenConfig): Warden {
	const strategies: Record<string, JwtStrategy> = {};

	if (config.jwt) {
		strategies.jwt = new JwtStrategy(config.jwt);
	}

	const manager = new AuthManager({
		defaultStrategy: config.defaultStrategy ?? "jwt",
		strategies,
	});

	return {
		verify: (token, strategy) => manager.verify(token, strategy),
		authenticate: (credentials, strategy) =>
			manager.authenticate(credentials, strategy),

		async generateToken(user: UserPayload): Promise<string> {
			const jwt = manager.getStrategy("jwt") as JwtStrategy;
			return jwt.signToken(user);
		},

		manager,

		expressMiddleware() {
			return (req, res, next) => {
				const headers = req.headers as Record<string, string> | undefined;
				const authHeader = headers?.authorization ?? "";
				const token =
					typeof authHeader === "string" && authHeader.startsWith("Bearer ")
						? authHeader.slice(7)
						: "";

				if (!token) {
					(res as { status: (n: number) => { json: (d: unknown) => void } })
						.status(401)
						.json({
							error: {
								code: "UNAUTHORIZED",
								message: "Missing authentication token",
							},
						});
					return;
				}

				manager
					.verify(token)
					.then((result) => {
						if (!result.authenticated || !result.user) {
							(res as { status: (n: number) => { json: (d: unknown) => void } })
								.status(401)
								.json({
									error: {
										code: "UNAUTHORIZED",
										message: result.error ?? "Authentication failed",
									},
								});
							return;
						}
						// Attach auth result to the request object (Express convention).
						req.auth = result;
						req.user = result.user;
						next();
					})
					.catch(() => {
						(res as { status: (n: number) => { json: (d: unknown) => void } })
							.status(500)
							.json({
								error: {
									code: "AUTH_ERROR",
									message: "Internal authentication error",
								},
							});
					});
			};
		},
	};
}
