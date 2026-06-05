/**
 * BasePolicy — extend it to group authorization checks for a resource. Action
 * methods are positional `(user, resource?) => AuthorizerResponse` (D3); decorate
 * a method with `@allowGuest()` / `@action({ allowGuest: true })` to let a guest
 * (null user) reach it. The optional `before` / `after` hooks run around every
 * action in the Adonis evaluation order (D5 — see PolicyAuthorizer).
 */

import type { UserPayload } from "../AuthManager.js";
import type { EffectivePermissions, Scope } from "../rights/types.js";
import type { AuthorizationResponse } from "./AuthorizationResponse.js";
import { emptyPermissions, getPolicyContext } from "./policyContext.js";
import type { HookResponse } from "./types.js";

export abstract class BasePolicy {
	/**
	 * Runs before the action. A non-`undefined` return short-circuits the action
	 * (a `boolean`/`AuthorizationResponse` becomes the result) — this is how a
	 * moderator bypass or an early `deny('not found', 404)` works, including for
	 * a guest. `undefined`/`void` falls through to the action.
	 */
	before?(
		user: UserPayload | null,
		action: string,
		...args: unknown[]
	): HookResponse;

	/**
	 * Runs after the action (or after a `before` short-circuit), receiving the
	 * resolved response. A non-`undefined` return overrides it; `undefined`
	 * keeps it.
	 */
	after?(
		user: UserPayload | null,
		action: string,
		result: AuthorizationResponse,
	): HookResponse;

	/**
	 * The Bouncer's active scope for the in-flight check (56.3). Defaults to
	 * `"global"` when the policy is used without a Bouncer context.
	 */
	protected get scope(): Scope {
		return getPolicyContext(this)?.scope ?? "global";
	}

	/**
	 * The resolved `EffectivePermissions` for the Bouncer's `(user, scope)` (56.3):
	 * role-derived ∪ ACL grants with global→tenant inheritance (per 56.1). A guest,
	 * a no-resolver Bouncer, or a standalone policy ⇒ empty permissions.
	 */
	protected get permissions(): EffectivePermissions {
		return getPolicyContext(this)?.permissions ?? emptyPermissions("global");
	}

	/**
	 * Tenant-isolation helper (D5 — enforceable, not automatic). `true` under the
	 * `global` scope (single-tenant — no boundary); under `{ tenant: T }` it is
	 * `resource.tenantId === T`. A policy enforces explicitly, e.g.
	 * `if (!this.sameTenant(post)) return false`.
	 */
	protected sameTenant(resource: { tenantId?: string | null }): boolean {
		const scope = this.scope;
		return scope === "global" ? true : resource.tenantId === scope.tenant;
	}
}
