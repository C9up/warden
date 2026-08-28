/**
 * MemoryRightsStore — the shipped in-memory rights driver.
 *
 * Implements the read-only `RightsStore` contract and adds chainable seeding
 * methods (`defineRole`/`assignRole`/`grant`/`revoke`) for app boot and tests.
 * DB-backed drivers are a documented copy-in adapter, not a hard dependency —
 * this driver keeps Warden's agnostic posture with zero new dependencies.
 *
 * Storage is Map-based, keyed by `scopeKey(scope)` then by role/userId, so
 * `global` and `tenant:X` rights stay isolated (inheritance is the resolver's
 * job, not the store's).
 */

import { type RightsStore, type Scope, scopeKey } from "./types.js";

export class MemoryRightsStore implements RightsStore {
	/** scopeKey → role → permissions */
	readonly #roleDefs = new Map<string, Map<string, Set<string>>>();
	/** scopeKey → userId → roles */
	readonly #userRoleMap = new Map<string, Map<string, Set<string>>>();
	/** scopeKey → userId → directly granted permissions */
	readonly #userGrantMap = new Map<string, Map<string, Set<string>>>();

	// — read contract —

	async rolePermissions(
		role: string,
		scope: Scope,
	): Promise<readonly string[]> {
		return snapshot(this.#roleDefs.get(scopeKey(scope))?.get(role));
	}

	async userRoles(userId: string, scope: Scope): Promise<readonly string[]> {
		return snapshot(this.#userRoleMap.get(scopeKey(scope))?.get(userId));
	}

	async userGrants(userId: string, scope: Scope): Promise<readonly string[]> {
		return snapshot(this.#userGrantMap.get(scopeKey(scope))?.get(userId));
	}

	// — seeding (in-memory driver only; not part of RightsStore) —

	defineRole(
		role: string,
		permissions: readonly string[],
		scope: Scope = "global",
	): this {
		const set = bucket(this.#roleDefs, scopeKey(scope), role);
		set.clear();
		for (const perm of permissions) set.add(perm);
		return this;
	}

	assignRole(userId: string, role: string, scope: Scope = "global"): this {
		bucket(this.#userRoleMap, scopeKey(scope), userId).add(role);
		return this;
	}

	grant(userId: string, permission: string, scope: Scope = "global"): this {
		bucket(this.#userGrantMap, scopeKey(scope), userId).add(permission);
		return this;
	}

	revoke(userId: string, permission: string, scope: Scope = "global"): this {
		this.#userGrantMap.get(scopeKey(scope))?.get(userId)?.delete(permission);
		return this;
	}
}

/** Defensive array snapshot — never hands back a live reference to internal state. */
function snapshot(set: Set<string> | undefined): readonly string[] {
	return set ? [...set] : [];
}

/** Get-or-create the inner `Set` for `outer[key][inner]`. */
function bucket(
	outer: Map<string, Map<string, Set<string>>>,
	key: string,
	inner: string,
): Set<string> {
	let mid = outer.get(key);
	if (!mid) {
		mid = new Map<string, Set<string>>();
		outer.set(key, mid);
	}
	let set = mid.get(inner);
	if (!set) {
		set = new Set<string>();
		mid.set(inner, set);
	}
	return set;
}
