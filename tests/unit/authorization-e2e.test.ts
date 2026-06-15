/**
 * AC2 — end-to-end authorization roundtrip (AC-E1/E3/E4).
 *
 * One cohesive flow exercising every facet TOGETHER through the real
 * `MemoryRightsStore` + `RightsResolver` + `Bouncer` (no stubs): RBAC role→perm,
 * ACL direct grant, ownership-in-policy, multi-tenant isolation + global→tenant
 * inheritance, and the `authorize()`→`WARDEN_AUTHORIZATION_FAILURE` throw. The
 * value here is the INTERACTION — the per-unit behaviour is pinned by
 * `bouncer-*`/`rights-resolver`/`memory-rights-store`; this proves they compose.
 *
 * Permissions are seeded ONLY through the store (role→perm + direct grant); a
 * token-carried `user.permissions` is asserted NOT to influence any decision
 * (D1/56.1 — the single resolution point is the rights model, not the JWT).
 */

import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import type { Scope } from "../../src/rights/types.js";

interface Post {
	authorId: string;
	tenantId?: string | null;
}

/** All four facets expressed as policy actions over the SAME resolved set. */
class PostPolicy extends BasePolicy {
	/** RBAC + ACL — both fold into `this.permissions` (the unification point). */
	edit(): boolean {
		return this.permissions.has("post.edit");
	}

	publish(): boolean {
		return this.permissions.has("post.publish");
	}

	/** Ownership — independent of any permission grant. */
	own(current: UserPayload, post: Post): boolean {
		return current.id === post.authorId;
	}

	/** Tenant-scoped permission with isolation enforced explicitly (D5). */
	archive(_current: UserPayload, post: Post): boolean {
		return this.sameTenant(post) && this.permissions.has("post.archive");
	}

	/** Global → tenant inheritance probe. */
	admin(): boolean {
		return this.permissions.has("system.admin");
	}
}

/** Seed every facet into ONE store so the flow reads from a single source. */
function seedStore(): MemoryRightsStore {
	return (
		new MemoryRightsStore()
			// RBAC — editor role grants post.edit; alice is an editor (global).
			.defineRole("editor", ["post.edit"], "global")
			.assignRole("alice", "editor", "global")
			// ACL — bob gets a direct grant, no role.
			.grant("bob", "post.publish", "global")
			// Tenant — manager grants post.archive in acme ONLY; carol is acme manager.
			.defineRole("manager", ["post.archive"], { tenant: "acme" })
			.assignRole("carol", "manager", { tenant: "acme" })
			// Global role whose permission inherits into every tenant scope.
			.defineRole("superadmin", ["system.admin"], "global")
			.assignRole("dave", "superadmin", "global")
	);
}

function bouncerFor(
	user: UserPayload,
	store: MemoryRightsStore,
	scope: Scope = "global",
): Bouncer {
	return new Bouncer(
		user,
		{},
		{ Post: PostPolicy },
		{ scope, resolver: new RightsResolver(store) },
	);
}

describe("warden > authorization e2e (AC2 — all facets in one flow)", () => {
	it("RBAC, ACL, ownership, tenant isolation + inheritance and the authorize-throw compose", async () => {
		const store = seedStore();

		// — RBAC: alice's editor role resolves to post.edit; a roleless user has none.
		expect(
			await bouncerFor({ id: "alice" }, store).with(PostPolicy).allows("edit"),
		).toBe(true);
		expect(
			await bouncerFor({ id: "nobody" }, store).with(PostPolicy).allows("edit"),
		).toBe(false);

		// — ACL: bob's direct grant allows publish, but a grant is not a role perm.
		expect(
			await bouncerFor({ id: "bob" }, store).with(PostPolicy).allows("publish"),
		).toBe(true);
		expect(
			await bouncerFor({ id: "bob" }, store).with(PostPolicy).allows("edit"),
		).toBe(false);

		// — Ownership: allowed iff the user owns the resource, regardless of perms.
		const post: Post = { authorId: "mallory" };
		expect(
			await bouncerFor({ id: "mallory" }, store)
				.with(PostPolicy)
				.allows("own", post),
		).toBe(true);
		expect(
			await bouncerFor({ id: "alice" }, store)
				.with(PostPolicy)
				.allows("own", post),
		).toBe(false);

		// — Tenant isolation: carol manages acme, not globex; sameTenant blocks a
		//   cross-tenant resource even within her own scope.
		const acmePost: Post = { authorId: "x", tenantId: "acme" };
		const globexPost: Post = { authorId: "x", tenantId: "globex" };
		expect(
			await bouncerFor({ id: "carol" }, store, { tenant: "acme" })
				.with(PostPolicy)
				.allows("archive", acmePost),
		).toBe(true);
		expect(
			await bouncerFor({ id: "carol" }, store, { tenant: "globex" })
				.with(PostPolicy)
				.allows("archive", globexPost),
		).toBe(false);
		expect(
			await bouncerFor({ id: "carol" }, store, { tenant: "acme" })
				.with(PostPolicy)
				.allows("archive", globexPost),
		).toBe(false);

		// — Global → tenant inheritance: dave's global superadmin perm reaches acme;
		//   carol (tenant-only manager) has no global system.admin there.
		expect(
			await bouncerFor({ id: "dave" }, store, { tenant: "acme" })
				.with(PostPolicy)
				.allows("admin"),
		).toBe(true);
		expect(
			await bouncerFor({ id: "carol" }, store, { tenant: "acme" })
				.with(PostPolicy)
				.allows("admin"),
		).toBe(false);

		// — HTTP throw: authorize() on a denial throws the mappable 403 failure.
		await expect(
			bouncerFor({ id: "nobody" }, store).with(PostPolicy).authorize("edit"),
		).rejects.toMatchObject({
			code: "WARDEN_AUTHORIZATION_FAILURE",
			status: 403,
		});
	});

	it("never lets a token-carried permission leak into a resolver decision (D1/56.1)", async () => {
		const store = seedStore();
		// eve carries post.edit as a JWT claim but has no role/grant in the store.
		const eve: UserPayload = { id: "eve", permissions: ["post.edit"] };
		expect(
			await bouncerFor(eve, store).with(PostPolicy).allows("edit"),
		).toBe(false);
	});
});
