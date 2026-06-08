/**
 * Bouncer evaluation contract — Layer 2 of Warden's unified authorization.
 *
 * The shapes here are faithful to AdonisJS Bouncer (verified context7
 * `/adonisjs/bouncer`, 2026-06-01): a predicate returns a boolean (sugar for
 * allow / deny) or an explicit `AuthorizationResponse`, sync or async.
 */

import type { UserPayload } from "../AuthManager.js";
import type { RightsResolver } from "../rights/RightsResolver.js";
import type { Scope } from "../rights/types.js";
import type { AuthorizationResponse } from "./AuthorizationResponse.js";

/**
 * Optional 4th `Bouncer` ctor argument (56.3, D1) — the scope dimension + the
 * Layer-1 resolver. Both optional; omitting it ⇒ the implicit `global` scope
 * with no resolver (single-tenant zero-config, D7). Additive: every 56.2 call
 * site keeps compiling.
 */
export interface BouncerContext {
	/** Active resolution scope. Defaults to `"global"`. */
	readonly scope?: Scope;
	/** Layer-1 resolver consulted for this Bouncer's `(user, scope)`. */
	readonly resolver?: RightsResolver;
}

/** A predicate's return — bool sugar or an explicit response, sync or async (D7). */
export type AuthorizerResponse =
	| boolean
	| AuthorizationResponse
	| Promise<boolean | AuthorizationResponse>;

/** A `before`/`after` hook return — like {@link AuthorizerResponse} plus `undefined` (fall-through). */
export type HookResponse =
	| boolean
	| AuthorizationResponse
	| undefined
	| Promise<boolean | AuthorizationResponse | undefined>;

/** Options accepted by `Bouncer.ability` and the `@action` decorator. */
export interface AbilityOptions {
	allowGuest?: boolean;
}

/**
 * An opaque ability reference produced by `Bouncer.ability`. Usable by-reference
 * (typed call args via the `Args` phantom) AND by-name (registered in the
 * Bouncer ctor's abilities record).
 *
 * `Args` is carried by the contravariant `__args` phantom — never read at
 * runtime — so a concrete `Ability<[Post]>` is assignable to the universal
 * `Ability<never[]>` storage type while `execute` stays invokable with the real
 * args. This is a branding pattern (carry the type parameter in the signature),
 * not a cast: `execute` itself takes `unknown[]` and the call sites validate
 * args via the phantom at the verb boundary.
 */
export interface Ability<Args extends unknown[] = unknown[]> {
	/** Whether a guest (null user) may invoke the callback (D5 step 2). */
	readonly allowGuest: boolean;
	/** Runs the ability callback. Guest-deny is applied by the evaluator, not here. */
	readonly execute: (
		user: UserPayload | null,
		...args: unknown[]
	) => AuthorizerResponse;
	/** Phantom — ties the by-reference call args to `Args`; never read at runtime. */
	readonly __args?: (...args: Args) => void;
}
