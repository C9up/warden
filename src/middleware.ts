/**
 * Warden auth middleware — resolves the AuthManager from the Ream IoC container
 * and authenticates the request using the configured strategy.
 *
 * Same pattern as `@c9up/blackhole/middleware` and AdonisJS `@adonisjs/auth`.
 *
 * @example
 *   // start/kernel.ts
 *   router.use([() => import('@c9up/warden/middleware')])
 *
 *   // On protected routes
 *   import { Guard } from '@c9up/warden'
 *   class OrderController {
 *     @Guard('jwt')
 *     async index(ctx) { ... }
 *   }
 */

import {
	AuthManager,
	type AuthResult,
	type AuthStrategy,
	sanitizePayload,
} from "./AuthManager.js";
import {
	getGuardMetadata,
	getPermissionMetadata,
	getRoleMetadata,
} from "./Guard.js";
import type { SessionStore } from "./strategies/SessionStrategy.js";

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

export interface WardenContext {
	request: {
		method: string;
		url: string;
		headers: Record<string, string>;
	};
	response: {
		status: (code: number) => void;
		json: (data: unknown) => void;
	};
	container: {
		resolve: (
			key: string | symbol | (abstract new (...args: never[]) => unknown),
		) => unknown;
	};
	/** Session store — set by a session middleware upstream. */
	session?: SessionStore;
	/** Set by the middleware after successful auth. */
	auth?: AuthResult;
	/** The route handler metadata (decorators). */
	route?: {
		controller?: object;
		action?: string | symbol;
	};
}

type WardenNext = () => Promise<void> | void;

/**
 * Ream auth middleware — resolves AuthManager from the container,
 * reads `@Guard`/`@Permission`/`@Role` metadata from the route handler,
 * and authenticates + authorizes the request.
 */
export async function wardenMiddleware(ctx: WardenContext, next: WardenNext) {
	const auth = ctx.container.resolve(AuthManager) as AuthManager;

	// Read guard metadata from the route handler (if declared via decorators).
	const controller = ctx.route?.controller;
	const action = ctx.route?.action;
	const strategies =
		controller && action ? getGuardMetadata(controller, action) : [];

	// No guard on this route — pass through (public endpoint).
	if (strategies.length === 0) {
		await next();
		return;
	}

	// Extract credentials from multiple sources:
	// 1. Authorization: Bearer <jwt> (JWT strategy)
	// 2. API key header — reads the header name from the ApiKeyStrategy config
	//    (defaults to 'x-api-key' if no ApiKeyStrategy is registered)
	// 3. Cookie/session (Session strategy — handled by the strategy itself via context)
	const authHeader = ctx.request.headers.authorization ?? "";
	const bearerToken = authHeader.startsWith("Bearer ")
		? authHeader.slice(7)
		: "";
	const apiKeyHeader = (() => {
		try {
			const s = auth.getStrategy("api-key");
			return (s as { headerName?: string }).headerName ?? "x-api-key";
		} catch {
			return "x-api-key";
		}
	})();
	// HTTP header names are case-insensitive. Node + every Ream-side
	// runtime lowercases incoming header keys, so an `ApiKeyStrategy`
	// declared with `headerName: "X-Custom-Key"` would never match the
	// incoming `x-custom-key` key without this normalisation — auth
	// would silently fail even with the right header on the wire.
	const apiKey = ctx.request.headers[apiKeyHeader.toLowerCase()] ?? "";

	const hasSessionStrategy = strategies.some((s) => s === "session");
	if (!bearerToken && !apiKey && !hasSessionStrategy) {
		ctx.response.status(401);
		ctx.response.json({
			error: {
				code: "UNAUTHORIZED",
				message: "Missing authentication token (Bearer or x-api-key)",
			},
		});
		return;
	}

	// Try each declared strategy. If every attempted strategy crashed AND none
	// succeeded, the caller returns 500 instead of 401 — a server-side incident
	// must stay observably distinct from a credential rejection.
	const { result, attemptCount, crashCount } = await tryAuthenticate(
		auth,
		strategies,
		{ bearerToken, apiKey, session: ctx.session, hasSessionStrategy },
	);

	if (!result?.authenticated || !result.user) {
		if (attemptCount > 0 && crashCount === attemptCount) {
			ctx.response.status(500);
			ctx.response.json({
				error: {
					code: "AUTH_STRATEGY_ERROR",
					message:
						"Authentication unavailable — one or more strategies failed. Check server logs.",
				},
			});
			return;
		}
		ctx.response.status(401);
		ctx.response.json({
			error: {
				code: "UNAUTHORIZED",
				message: result?.error ?? "Authentication failed",
			},
		});
		return;
	}

	const user = result.user;

	// Permission + role checks are independent AND gates: the user must satisfy
	// ALL required permissions AND ALL required roles. Having a role does NOT
	// bypass permission checks. This is the strictest model — callers who want
	// role-OR-permission semantics should use a custom guard instead.
	if (controller && action) {
		const denied = await checkAuthorization(auth, user, controller, action);
		if (denied) {
			ctx.response.status(403);
			ctx.response.json({ error: { code: "FORBIDDEN", message: denied } });
			return;
		}
	}

	// Auth successful — attach to context and continue.
	ctx.auth = result;
	await next();
}

/**
 * Try each declared strategy in order — session strategies via
 * `verifyWithContext()`, others via `verify(token)` with native-first credential
 * fallback. Distinguishes crashes (strategy threw / `strategyCrash`) from
 * credential rejections so the caller can return 500 vs 401.
 */
async function tryAuthenticate(
	auth: AuthManager,
	strategies: string[],
	creds: {
		bearerToken: string;
		apiKey: string;
		session: SessionStore | undefined;
		hasSessionStrategy: boolean;
	},
): Promise<{
	result: AuthResult | null;
	attemptCount: number;
	crashCount: number;
}> {
	const { bearerToken, apiKey, session } = creds;
	let result: AuthResult | null = null;
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
				// Bearer no longer masks a valid API key for the api-key strategy).
				const credential =
					strategyName === "api-key"
						? apiKey || bearerToken
						: bearerToken || apiKey;
				if (!credential) continue;
				attemptCount++;
				r = await auth.verify(credential, strategyName);
			}
			if (r.authenticated) {
				result = r;
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
	return { result, attemptCount, crashCount };
}

/**
 * Gate the authenticated user against the route's @Permission / @Role decorators.
 * Both are independent AND gates resolved ONCE against the same unified
 * EffectivePermissions set (Epic 56, D7). Returns the FORBIDDEN message, or null
 * when authorised (and zero-cost when neither decorator is present).
 */
async function checkAuthorization(
	auth: AuthManager,
	user: NonNullable<AuthResult["user"]>,
	controller: object,
	action: string | symbol,
): Promise<string | null> {
	const requiredPermissions = getPermissionMetadata(controller, action);
	const requiredRoles = getRoleMetadata(controller, action);
	if (requiredPermissions.length === 0 && requiredRoles.length === 0) {
		return null;
	}
	const effective = await auth.resolvePermissions(user, "global");
	if (requiredPermissions.length > 0) {
		const missing = requiredPermissions.filter((p) => !effective.has(p));
		if (missing.length > 0) return `Missing permissions: ${missing.join(", ")}`;
	}
	if (requiredRoles.length > 0) {
		const missing = requiredRoles.filter((r) => !effective.roles.has(r));
		if (missing.length > 0) return `Missing roles: ${missing.join(", ")}`;
	}
	return null;
}
