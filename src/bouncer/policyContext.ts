/**
 * Internal policy context attach — Layer-2 ⨯ Layer-1 wiring (Epic 56, story 56.3).
 *
 * The active `scope` and the resolved `EffectivePermissions` for the in-flight
 * `(user, scope)` are attached to a freshly-constructed policy via a package-
 * internal `WeakMap` (D2) — NOT a public setter on `BasePolicy` and NOT barrelled.
 * `BasePolicy`'s `this.scope` / `this.permissions` getters read it back; the
 * `PolicyAuthorizer` writes it before dispatch. A policy used without a Bouncer
 * has no entry, so the getters fall back to `global` + {@link emptyPermissions}.
 */

import type { EffectivePermissions, Scope } from "../rights/types.js";
import type { BasePolicy } from "./BasePolicy.js";

/** What the authorizer attaches to a policy instance for one check. */
export interface PolicyContext {
	readonly scope: Scope;
	readonly permissions: EffectivePermissions;
}

const contexts = new WeakMap<BasePolicy, PolicyContext>();

/** Attach the active scope + resolved permissions to a policy instance (internal). */
export function setPolicyContext(
	policy: BasePolicy,
	context: PolicyContext,
): void {
	contexts.set(policy, context);
}

/** Read back a policy's attached context, or `undefined` when used standalone. */
export function getPolicyContext(
	policy: BasePolicy,
): PolicyContext | undefined {
	return contexts.get(policy);
}

/**
 * The empty `EffectivePermissions` for a guest / no-resolver Bouncer (D9). Built
 * locally — never a `resolve()` call (the resolver requires a non-null user) and
 * never importing 56.1's non-exported `ResolvedPermissions`. `has` → false;
 * `hasAll([])` → true (vacuous); `hasAny` → false; empty sets; `scope` = active.
 */
export function emptyPermissions(scope: Scope): EffectivePermissions {
	return {
		has: () => false,
		hasAll: (permissions) => permissions.length === 0,
		hasAny: () => false,
		permissions: new Set<string>(),
		roles: new Set<string>(),
		scope,
	};
}
