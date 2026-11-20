/**
 * RightsResolver — computes a user's effective permissions for a scope.
 *
 * This is the unification point the epic calls `user.permissions`: every later
 * authorization facet consults `resolve(user, scope)` instead of reading roles
 * or permissions ad hoc.
 *
 * Resolution rules:
 *   - Scope chain: `["global"]` for global, `["global", { tenant }]` for a
 *     tenant scope — global rights are inherited into every tenant scope.
 *   - Roles: token-carried `user.roles` are global identity — they apply at
 *     the `global` link only; each scope additionally uses `store.userRoles(...)`.
 *     A global role's global permissions still inherit into tenant scopes via
 *     the chain, but a payload role never picks up a same-named tenant role's
 *     permissions (no cross-tenant escalation by name collision).
 *   - Permissions = (∪ over roles of `store.rolePermissions(...)`) ∪
 *     `store.userGrants(...)` (the ACL). The payload's `user.permissions` is
 *     NOT an input — permissions are derived from the rights model only.
 *   - Fail-closed: absent data contributes nothing and never throws.
 *   - Exact-match comparison; no wildcard or role-hierarchy expansion.
 */

import type { UserPayload } from "../AuthManager.js";
import type { EffectivePermissions, RightsStore, Scope } from "./types.js";

class ResolvedPermissions implements EffectivePermissions {
	constructor(
		readonly permissions: ReadonlySet<string>,
		readonly roles: ReadonlySet<string>,
		readonly scope: Scope,
	) {}

	has(permission: string): boolean {
		return this.permissions.has(permission);
	}

	hasAll(permissions: readonly string[]): boolean {
		return permissions.every((p) => this.permissions.has(p));
	}

	hasAny(permissions: readonly string[]): boolean {
		return permissions.some((p) => this.permissions.has(p));
	}
}

/**
 * `effective` as the REQUEST may use it: when the user came in with an access
 * token, every permission must also be allowed by that token.
 *
 * The one place the intersection happens for a resolved set, so the coarse
 * helpers (`AuthManager.hasPermission`, the decorator gate) and a policy's
 * `this.permissions` cannot answer differently for the same request. Roles stay
 * the user's: a token restricts what may be DONE, not who the user is.
 */
export function narrowToAccessToken(
	effective: EffectivePermissions,
	user: UserPayload,
): EffectivePermissions {
	const token = user.currentAccessToken;
	if (token === undefined) return effective;
	const allowed = (permission: string): boolean =>
		effective.has(permission) && token.allows(permission);
	return {
		has: allowed,
		hasAll: (permissions) => permissions.every(allowed),
		hasAny: (permissions) => permissions.some(allowed),
		permissions: new Set([...effective.permissions].filter(allowed)),
		roles: effective.roles,
		scope: effective.scope,
	};
}

export class RightsResolver {
	constructor(private readonly store: RightsStore) {}

	async resolve(
		user: UserPayload,
		scope: Scope = "global",
	): Promise<EffectivePermissions> {
		const chain: Scope[] = scope === "global" ? ["global"] : ["global", scope];

		const roles = new Set<string>();
		const permissions = new Set<string>();
		const payloadRoles = user.roles ?? [];

		for (const link of chain) {
			const storeRoles = await this.store.userRoles(user.id, link);
			// Token-carried roles are global identity: they contribute at the
			// `global` link only, so a payload role never inherits a same-named
			// tenant role's permissions. A global role's global permissions still
			// reach tenant scopes via the chain.
			const scopeRoles =
				link === "global"
					? new Set<string>([...payloadRoles, ...storeRoles])
					: new Set<string>(storeRoles);

			for (const role of scopeRoles) {
				roles.add(role);
				for (const perm of await this.store.rolePermissions(role, link)) {
					permissions.add(perm);
				}
			}

			for (const grant of await this.store.userGrants(user.id, link)) {
				permissions.add(grant);
			}
		}

		return new ResolvedPermissions(permissions, roles, scope);
	}
}
