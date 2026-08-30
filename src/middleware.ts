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

import { Authenticator } from "./Authenticator.js";
import { AuthManager, type UserPayload } from "./AuthManager.js";
import type { BasePolicy } from "./bouncer/BasePolicy.js";
import { Bouncer } from "./bouncer/Bouncer.js";
import type { Ability, PolicyContainerResolver } from "./bouncer/types.js";
import type { ScopeRequestContext } from "./config.js";
import { E_UNAUTHORIZED_ACCESS, WardenError } from "./errors.js";
import {
	getGuardMetadata,
	getPermissionMetadata,
	getRequireMfaMetadata,
	getRoleMetadata,
} from "./Guard.js";
import { RightsResolver } from "./rights/RightsResolver.js";
import type { Scope } from "./rights/types.js";
import type { SessionStore } from "./strategies/SessionStrategy.js";

/**
 * Tokens warden resolves from the container: a service class, or a string/symbol
 * alias (`"bouncer:registry"`). Mirrors Ream's `ServiceToken` without importing
 * it — warden declares the shape so it stays framework-agnostic.
 */
type ResolvableToken =
	| string
	| symbol
	| (abstract new (
			...args: never[]
	  ) => unknown);

/**
 * Per-request IoC resolver Ream exposes as `ctx.containerResolver` (Adonis
 * idiom). Warden resolves AuthManager / RightsResolver / the bouncer registry
 * through this — reading from the context it is HANDED — so the package never
 * imports `@c9up/ream` at runtime. A host that provides none (non-Ream, or a
 * misconfigured kernel) yields no resolution: guarded routes fail CLOSED.
 */
interface ContainerResolver {
	make(token: ResolvableToken): Promise<unknown>;
}

/**
 * Adapt the request resolver to the shape the Bouncer needs for policy DI.
 *
 * The context resolver is deliberately untyped (`Promise<unknown>`) — it
 * resolves string tokens too. `instanceof` is what proves the instance is the
 * policy that was asked for: a real check rather than an assertion, and it
 * catches a host resolver that hands back something else instead of letting a
 * wrong object reach the policy's methods.
 */
function policyResolver(
	resolver: ContainerResolver | undefined,
): PolicyContainerResolver | undefined {
	if (resolver === undefined) return undefined;
	return {
		async make<T>(ctor: new (...args: never[]) => T): Promise<T> {
			const instance = await resolver.make(ctor);
			if (!(instance instanceof ctor)) {
				throw new WardenError(
					"POLICY_RESOLUTION_FAILED",
					`The container resolved "${ctor.name}" to something else — a policy must be an instance of the class that was requested.`,
				);
			}
			return instance;
		},
	};
}

/**
 * Agnostic authorization slot — structurally Ream's `Authorizer` interface (and
 * Adonis's bouncer contract): `allows` / `denies` / `authorize`. Typed as the
 * interface, NOT the concrete `Bouncer`, so a real Ream `HttpContext` — whose
 * `bouncer` is this same agnostic shape — is assignable to `WardenContext`
 * without warden importing `@c9up/ream`. `initializeBouncer` fills the slot with
 * a concrete `Bouncer`, which satisfies this contract.
 */
interface Authorizer {
	allows(ability: string, ...args: unknown[]): Promise<boolean>;
	denies(ability: string, ...args: unknown[]): Promise<boolean>;
	authorize(ability: string, ...args: unknown[]): Promise<void>;
}

export interface WardenContext {
	request: {
		/** Ream's `HttpContext` exposes headers as a METHOD, not a property. */
		headers(): Record<string, string>;
		/** Read the encrypted remember-me cookie back. Optional, like its writer. */
		encryptedCookie?: (name: string) => string | null;
	};
	/**
	 * Per-request IoC resolver (Ream's `ctx.containerResolver`). Warden resolves
	 * AuthManager + the bouncer registry through it — agnostic, no `@c9up/ream`
	 * import. Absent on a non-Ream host → guarded routes fail closed.
	 */
	containerResolver?: ContainerResolver;
	response: {
		status: (code: number) => unknown;
		json: (data: unknown) => void;
		/**
		 * Write an ENCRYPTED cookie, for the remember-me token. Optional: a
		 * host without it simply cannot offer "keep me signed in", and
		 * `login(user, true)` says so rather than pretending.
		 *
		 * Encrypted and not merely signed, because the value IS the credential
		 * — anyone who reads it can present it.
		 */
		encryptedCookie?: (
			name: string,
			value: string,
			options?: Record<string, unknown>,
		) => unknown;
		/** Drop a cookie (used to clear the remember-me one). */
		clearCookie?: (name: string, options?: Record<string, unknown>) => unknown;
		/**
		 * Redirect the response (Ream's `ctx.response.redirect`). Optional so a
		 * minimal host without it still gets the 401 JSON fallback — Warden does
		 * its own content negotiation (see `renderAuthError`) rather than leaning
		 * on the host's exception handler.
		 */
		redirect?: (url: string) => unknown;
	};
	/**
	 * Matched-route info — Ream (like Adonis) exposes the controller class +
	 * method under `ctx.route` (`ctx.route.controller` / `ctx.route.action`),
	 * NOT top-level. This is the primary source the guard-metadata lookup reads.
	 * Absent for inline-function routes. (context7 `/adonisjs/v7-docs`: "access
	 * the currently matched route via `ctx.route`".)
	 */
	route?: {
		controller?: object;
		action?: string | symbol;
	};
	/**
	 * Top-level controller/action — kept only as a FALLBACK for hosts that
	 * expose them flat. Ream uses `ctx.route` (above); the lookup prefers it.
	 */
	controller?: object;
	action?: string | symbol;
	/** Session store — set by a session middleware upstream. */
	session?: SessionStore;
	/**
	 * Ream's `ctx.auth` slot. Typed STRUCTURALLY (agnostic — like `bouncer` below),
	 * NOT as the concrete {@link Authenticator}: that class has `#private` fields,
	 * which makes it nominal, so Ream's `HttpContext.auth` (an `AuthState`) could
	 * never satisfy it and warden's middleware would fail to typecheck as a Ream
	 * `MiddlewareClass`. `silentAuth`/`wardenMiddleware` fill it with a concrete
	 * `Authenticator` (narrowed here via `instanceof`); inline handlers then call
	 * `ctx.auth.authenticate()` / `ctx.auth.use('session').login(user)` on it.
	 */
	auth?: {
		isAuthenticated?: boolean;
		user?: {
			id: string;
			email?: string;
			roles?: string[];
			permissions?: string[];
			[key: string]: unknown;
		};
		roles?: string[];
		permissions?: string[];
		authenticate?(): Promise<void>;
		check?(): Promise<boolean>;
		getUserOrFail?(): { id: string; [key: string]: unknown } | undefined;
		use?(name: string): unknown;
		readonly authenticationAttempted?: boolean;
	};
	/**
	 * Per-request authorization entry point — set by `initializeBouncer`. Typed
	 * as the agnostic {@link Authorizer} contract (Ream's `ctx.bouncer` slot),
	 * filled with a concrete `Bouncer` at runtime.
	 */
	bouncer?: Authorizer;
}

/**
 * Resolve a token from the request's IoC resolver (`ctx.containerResolver`,
 * Adonis idiom). Returns undefined when no resolver is present or the token is
 * unbound — callers decide fail-open (the bouncer registry) vs fail-closed (the
 * AuthManager gate in `wardenMiddleware`). No `@c9up/ream` import: warden reads
 * only from the context Ream hands it.
 */
async function resolveFromCtx(
	ctx: WardenContext,
	token: ResolvableToken,
): Promise<unknown> {
	try {
		return await ctx.containerResolver?.make(token);
	} catch {
		return undefined;
	}
}

/**
 * Bridge Ream's ctx to the `resolveScope` hook's `ScopeRequestContext`, which
 * takes headers as a plain object (a snapshot) — keeps the app-facing hook
 * contract stable while warden reads Ream's `headers()` method internally.
 */
function toScopeContext(ctx: WardenContext): ScopeRequestContext {
	return { request: { headers: ctx.request.headers() }, auth: ctx.auth };
}

type WardenNext = () => Promise<void> | void;

/**
 * Ream auth middleware — resolves AuthManager from the container,
 * reads `@Guard`/`@Permission`/`@Role` metadata from the route handler,
 * and authenticates + authorizes the request.
 */
export async function wardenMiddleware(ctx: WardenContext, next: WardenNext) {
	const resolvedAuth = await resolveFromCtx(ctx, AuthManager);
	if (!(resolvedAuth instanceof AuthManager)) {
		// Fail CLOSED — a missing AuthManager (WardenProvider not registered, or
		// no `ctx.containerResolver` on a non-Ream host) must never silently let
		// a guarded request through.
		throw new WardenError(
			"AUTH_NOT_REGISTERED",
			"AuthManager is not registered in the container — add WardenProvider to your providers list.",
		);
	}
	const auth = resolvedAuth;

	// Read guard metadata from the route handler (if declared via decorators).
	// Ream (like Adonis) exposes the controller/method under `ctx.route`; fall
	// back to top-level only for hosts that expose them flat. Reading the wrong
	// place silently yields `[]` guards → guarded routes treated as public
	// (fail-open) — the exact bug this precedence prevents.
	const controller = ctx.route?.controller ?? ctx.controller;
	const action = ctx.route?.action ?? ctx.action;
	const strategies =
		controller && action ? getGuardMetadata(controller, action) : [];

	// No guard on this route — pass through (public endpoint).
	if (strategies.length === 0) {
		await next();
		return;
	}

	// Delegate authentication to the per-request Authenticator (the SAME contract
	// inline handlers use via `ctx.auth.authenticate()`), so the decorator path
	// and the functional path share one code path. It sets `ctx.auth` and throws
	// on failure — E_UNAUTHORIZED_ACCESS (401, credential rejection) or a
	// WARDEN_AUTH_STRATEGY_ERROR (500, every attempted guard crashed).
	const authenticator = ensureAuthenticator(ctx, auth);
	const loginRoute = await resolveLoginRoute(ctx);
	try {
		await authenticator.authenticateUsing(strategies, { loginRoute });
	} catch (err) {
		if (err instanceof E_UNAUTHORIZED_ACCESS) {
			renderAuthError(ctx, err);
			return;
		}
		// Every attempted guard crashed → server-side incident, mapped to 500 so
		// it stays observably distinct from a credential rejection.
		if (err instanceof WardenError && err.status === 500) {
			ctx.response.status(500);
			ctx.response.json({
				error: { code: "AUTH_STRATEGY_ERROR", message: err.message },
			});
			return;
		}
		throw err;
	}

	const user = authenticator.getUserOrFail();

	// Permission + role checks are independent AND gates: the user must satisfy
	// ALL required permissions AND ALL required roles. Having a role does NOT
	// bypass permission checks. This is the strictest model — callers who want
	// role-OR-permission semantics should use a custom guard instead.
	if (controller && action) {
		const scope = await resolveRequestScope(ctx);
		const denied = await checkAuthorization(
			auth,
			user,
			controller,
			action,
			scope,
		);
		if (denied) {
			ctx.response.status(403);
			ctx.response.json({ error: { code: "FORBIDDEN", message: denied } });
			return;
		}

		// @RequireMfa gate: the user must carry a truthy `mfa` claim, set by the
		// app's step-up flow once MfaManager.verify() succeeds.
		if (getRequireMfaMetadata(controller, action) && user.mfa !== true) {
			ctx.response.status(403);
			ctx.response.json({
				error: {
					code: "MFA_REQUIRED",
					message: "Multi-factor authentication is required for this action.",
				},
			});
			return;
		}
	}

	// Auth successful — `ctx.auth` (the Authenticator) already carries the user.
	await next();
}

/**
 * Silent auth middleware (AdonisJS `silent_auth` parity) — a GLOBAL middleware
 * that populates `ctx.auth` from the request's credentials when they're valid,
 * and NEVER throws / 401s when they're absent or invalid. Register it for every
 * route, BEFORE `wardenMiddleware` and any tenant middleware that reads
 * `ctx.auth.user`.
 *
 * Why it exists: `wardenMiddleware` only authenticates routes carrying `@Guard`
 * decorator metadata (`ctx.route.controller/action`). Inline routes — a
 * `router.post('/rpc', handler)`, relay frames, any `RouteBuilder.guard()`
 * route — expose no controller/action, so warden never populates `ctx.auth` for
 * them and a downstream enforcement (Ream's route-level guard check, or the
 * RpcRouter's per-method `.guard()`) rejects every call even with a valid token.
 * silentAuth fills `ctx.auth` so that downstream enforcement can do its job; it
 * decides nothing itself — exactly Adonis (`silent_auth` populates, the `auth`
 * middleware / route guard enforces).
 *
 * Uses the AuthManager's DEFAULT strategy (Adonis's "default guard"). A missing
 * AuthManager leaves the request a guest with `ctx.auth` unset; otherwise
 * `ctx.auth` is ALWAYS set to an {@link Authenticator} (AdonisJS
 * `initialize_auth_middleware` parity) — populated when credentials verify,
 * left as a guest (`isAuthenticated === false`) when they're absent, invalid, or
 * a guard crashes. Silent auth NEVER surfaces a 401/500.
 */
export async function silentAuth(ctx: WardenContext, next: WardenNext) {
	const resolvedAuth = await resolveFromCtx(ctx, AuthManager);
	// Non-enforcing: a host without warden wired runs as guest. (Enforcement
	// middlewares fail CLOSED on a missing AuthManager; silent auth does not.)
	if (!(resolvedAuth instanceof AuthManager)) {
		await next();
		return;
	}
	const authenticator = ensureAuthenticator(ctx, resolvedAuth);
	try {
		// `check()` runs the default guard and returns a boolean instead of
		// throwing on a credential rejection; the catch swallows the residual
		// crash/config path so silent auth stays strictly non-enforcing.
		await authenticator.check();
	} catch {
		// Guard crash / config error → stay a guest, never surface here.
	}
	await next();
}

/**
 * Merge values into the request's view state, when the app has a template
 * layer. A no-op outside an HTTP render, or in an app with no views.
 */
function shareWithView(
	ctx: WardenContext,
	values: Record<string, unknown>,
): void {
	const view = Reflect.get(Object(ctx), "view");
	const share = Reflect.get(Object(view), "share");
	if (typeof share === "function") share.call(view, values);
}

/**
 * Reuse the request's Authenticator if one is already attached (e.g. `silentAuth`
 * ran first), else build and attach a fresh one. Keeps `ctx.auth` a single
 * per-request instance across the middleware chain.
 */
function ensureAuthenticator(
	ctx: WardenContext,
	auth: AuthManager,
): Authenticator {
	if (ctx.auth instanceof Authenticator) return ctx.auth;
	const authenticator = new Authenticator(ctx, auth);
	ctx.auth = authenticator;
	// Share it with the request's view, as AdonisJS's auth does, so a migrated
	// template reads `{{ auth.user.email }}` / `@if(auth.isAuthenticated)`
	// unchanged. Both middlewares funnel through here, so one share covers them.
	shareWithView(ctx, { auth: authenticator });
	return authenticator;
}

/**
 * Optional login route (`ctx.response.redirect` target for session-guard HTML
 * flows). Registered by `WardenProvider` from `config.auth.loginRoute` under the
 * `"warden:loginRoute"` token; absent ⇒ no redirect (401 JSON).
 */
async function resolveLoginRoute(
	ctx: WardenContext,
): Promise<string | undefined> {
	const value = await resolveFromCtx(ctx, "warden:loginRoute");
	return typeof value === "string" ? value : undefined;
}

/**
 * Render an `E_UNAUTHORIZED_ACCESS` to the response — Warden does its OWN content
 * negotiation (AdonisJS session renderer parity) instead of leaning on the
 * host's exception handler, so it stays agnostic. An `Accept: text/html` request
 * against a session guard carrying a `redirectTo` is redirected to the login
 * route; every other case gets a 401 JSON body. Always fail-closed.
 */
export function renderAuthError(
	ctx: WardenContext,
	error: E_UNAUTHORIZED_ACCESS,
): void {
	const accept = ctx.request.headers().accept ?? "";
	const wantsHtml = accept.includes("text/html");
	if (wantsHtml && error.redirectTo && ctx.response.redirect) {
		ctx.response.redirect(error.redirectTo);
		return;
	}
	ctx.response.status(error.status ?? 401);
	ctx.response.json({
		error: { code: error.code, message: error.message },
	});
}

/**
 * The abilities/policies/scope-resolver a per-request Bouncer is built from.
 * Registered once by `WardenProvider` (from `config.auth`) under the container
 * token `"bouncer:registry"`; read fresh by `initializeBouncer` per request.
 */
export interface BouncerRegistry {
	abilities: Record<string, Ability<never[]>>;
	policies: Record<string, new () => BasePolicy>;
	resolveScope?: (ctx: ScopeRequestContext) => Scope | Promise<Scope>;
}

/**
 * Bouncer initializer (Epic 56.6) — a GLOBAL middleware (register it for every
 * route, after `wardenMiddleware`). It builds the per-request {@link Bouncer}
 * from the authenticated user (`ctx.auth?.user`, or `null` for a guest), the
 * shared `RightsResolver`, and the registered abilities/policies, then attaches
 * it as `ctx.bouncer`. Handlers authorize via `await ctx.bouncer.authorize(...)`
 * (throws `WARDEN_AUTHORIZATION_FAILURE` carrying `status: 403`, which the host's
 * ExceptionHandler maps to a 403 response) or branch on `ctx.bouncer.allows(...)`.
 *
 * Unlike `wardenMiddleware` (a per-route GUARD that short-circuits public
 * routes), this runs on EVERY request so `ctx.bouncer` is always available —
 * including for guests — matching AdonisJS's `initialize_bouncer_middleware`.
 */
export async function initializeBouncer(ctx: WardenContext, next: WardenNext) {
	// Both dependencies are registered by WardenProvider. Resolve defensively:
	// a host that wired the middleware but not the provider gets an empty Bouncer
	// (no abilities/resolver) rather than a crash on every request.
	const resolved = await tryResolve(ctx, RightsResolver);
	const resolver = resolved instanceof RightsResolver ? resolved : undefined;
	const candidate = await tryResolve(ctx, "bouncer:registry");
	const registry = isBouncerRegistry(candidate) ? candidate : undefined;

	const user = ctx.auth?.user ?? null;
	const scope: Scope = registry?.resolveScope
		? await registry.resolveScope(toScopeContext(ctx))
		: "global";

	const bouncer = new Bouncer(user, registry?.abilities, registry?.policies, {
		scope,
		resolver,
		// The REQUEST's resolver, so a policy taking constructor dependencies
		// gets them — and gets this request's, not the application container's.
		// It was never passed, so `@inject()` on a policy silently resolved to a
		// plain `new Policy()` with no dependencies at all.
		containerResolver: policyResolver(ctx.containerResolver),
	});
	ctx.bouncer = bouncer;
	// Share the checks with the request's view so `@can(...)` resolves them,
	// as AdonisJS's own middleware does.
	shareWithView(ctx, bouncer.templateHelpers);
	await next();
}

/** Resolve a container token from the request resolver, returning undefined instead of throwing when absent. */
async function tryResolve(
	ctx: WardenContext,
	token: ResolvableToken,
): Promise<unknown> {
	return resolveFromCtx(ctx, token);
}

/** Structural guard — the registry is a plain object carrying ability/policy tables. */
function isBouncerRegistry(value: unknown): value is BouncerRegistry {
	return (
		typeof value === "object" &&
		value !== null &&
		"abilities" in value &&
		"policies" in value
	);
}

/**
 * Resolve the request's authorization scope from the registry's `resolveScope`
 * hook (default `"global"`). Shared so the @Role/@Permission decorator gate and
 * the Bouncer path evaluate in the SAME scope — without this the decorator path
 * hardcoded "global" and tenant-scoped roles/grants never satisfied @Role/@Permission.
 */
async function resolveRequestScope(ctx: WardenContext): Promise<Scope> {
	const candidate = await tryResolve(ctx, "bouncer:registry");
	const registry = isBouncerRegistry(candidate) ? candidate : undefined;
	return registry?.resolveScope
		? await registry.resolveScope(toScopeContext(ctx))
		: "global";
}

/**
 * Gate the authenticated user against the route's @Permission / @Role decorators.
 * Both are independent AND gates resolved ONCE against the same unified
 * EffectivePermissions set (Epic 56, D7). Returns the FORBIDDEN message, or null
 * when authorised (and zero-cost when neither decorator is present).
 */
async function checkAuthorization(
	auth: AuthManager,
	user: UserPayload,
	controller: object,
	action: string | symbol,
	scope: Scope,
): Promise<string | null> {
	const requiredPermissions = getPermissionMetadata(controller, action);
	const requiredRoles = getRoleMetadata(controller, action);
	if (requiredPermissions.length === 0 && requiredRoles.length === 0) {
		return null;
	}
	const effective = await auth.resolvePermissions(user, scope);
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

/**
 * Default export — the Adonis-style class form Ream's lazy middleware resolver
 * expects (`new mod.default().handle(ctx, next)`). Without it the documented
 * `router.use([() => import('@c9up/warden/middleware')])` crashes with
 * `new undefined()`. The named `wardenMiddleware` / `initializeBouncer` stay for
 * direct registration `router.use([wardenMiddleware])`.
 */
export default class WardenMiddleware {
	handle(ctx: WardenContext, next: WardenNext): Promise<void> {
		return wardenMiddleware(ctx, next);
	}
}
