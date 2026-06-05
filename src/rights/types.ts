/**
 * Rights data model — Layer 1 of Warden's unified authorization (Epic 56).
 *
 * The single resolution point: `resolve(user, scope) → EffectivePermissions`.
 * Roles → permissions (RBAC) and direct user → permission grants (ACL) are
 * both keyed by scope (`global` | `{ tenant }`). The store contract is
 * read-only; concrete drivers (the shipped in-memory one, or a copy-in DB
 * adapter) provide seeding/mutation on top.
 */

/**
 * Resolution scope. `"global"` is the implicit single-tenant scope; a tenant
 * scope is the discriminated object form so it stays type-distinguishable from
 * the global sentinel at call sites.
 */
export type Scope = "global" | { readonly tenant: string };

/**
 * The single unification point — a user's effective permissions within a scope.
 */
export interface EffectivePermissions {
	/** True iff the permission is in the resolved set (exact match). */
	has(permission: string): boolean;
	/** True iff ALL listed permissions are present (empty list ⇒ vacuously true). */
	hasAll(permissions: readonly string[]): boolean;
	/** True iff ANY listed permission is present (empty list ⇒ false). */
	hasAny(permissions: readonly string[]): boolean;
	/** The user's effective permissions in this scope (role-derived ∪ direct grants). */
	readonly permissions: ReadonlySet<string>;
	/** The roles that contributed (payload ∪ store, within the resolved scope incl. global). */
	readonly roles: ReadonlySet<string>;
	/** The scope this was resolved for. */
	readonly scope: Scope;
}

/**
 * Read contract consulted by the resolver. All methods scoped + async: a
 * DB-backed adapter is inherently async, and the evaluation layer (56.2) is
 * async end-to-end. Writes are NOT part of this contract — drivers add their
 * own seeding API.
 */
export interface RightsStore {
	/** Permissions a role grants in the given scope (unknown role ⇒ []). */
	rolePermissions(role: string, scope: Scope): Promise<readonly string[]>;
	/** Roles assigned to a user in the given scope (none ⇒ []). */
	userRoles(userId: string, scope: Scope): Promise<readonly string[]>;
	/** Direct per-user permission grants (ACL) in the given scope (none ⇒ []). */
	userGrants(userId: string, scope: Scope): Promise<readonly string[]>;
}

/**
 * Stable string key for a scope. `"global"` → `"global"`,
 * `{ tenant: "X" }` → `"tenant:X"`. Used by drivers to key their storage and
 * by 56.3 when threading scope through the evaluation context.
 */
export function scopeKey(scope: Scope): string {
	return scope === "global" ? "global" : `tenant:${scope.tenant}`;
}
