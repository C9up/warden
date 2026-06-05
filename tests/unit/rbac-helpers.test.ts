import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { AuthManager, type AuthStrategy } from "../../src/AuthManager.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";

// Minimal strategy — AuthManager requires ≥1 registered strategy at
// construction; these coarse-helper tests never exercise authentication.
const jwt: AuthStrategy = {
	name: "jwt",
	async authenticate() {
		return { authenticated: false };
	},
	async verify() {
		return { authenticated: false };
	},
};

function makeAuth(rights?: RightsResolver): AuthManager {
	return new AuthManager({
		defaultStrategy: "jwt",
		strategies: { jwt },
		rights,
	});
}

/** Reads a permission off the 56.3-attached EffectivePermissions (policy path). */
class PostPolicy extends BasePolicy {
	edit(): boolean {
		return this.permissions.has("post.edit");
	}
	remove(): boolean {
		return this.permissions.has("post.delete");
	}
}

describe("warden > coarse RBAC helpers re-expressed over the resolver (56.4)", () => {
	it("derives permissions from role-derived ∪ direct grants, never the token (D1)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("editor", ["post.edit"])
			.assignRole("u1", "editor")
			.grant("u1", "post.delete");
		const auth = makeAuth(new RightsResolver(store));
		// `post.publish` is carried in the token payload — and must be ignored.
		const u: UserPayload = { id: "u1", permissions: ["post.publish"] };

		expect(await auth.hasPermission(u, "post.edit")).toBe(true); // role-derived
		expect(await auth.hasPermission(u, "post.delete")).toBe(true); // direct grant
		expect(await auth.hasPermission(u, "post.publish")).toBe(false); // token-only ⇒ D1
		expect(await auth.hasPermission(u, "post.archive")).toBe(false); // unseeded
	});

	it("reflects payload roles ∪ store roles for hasRole (D2)", async () => {
		const store = new MemoryRightsStore().assignRole("u1", "auditor");
		const auth = makeAuth(new RightsResolver(store));
		const u: UserPayload = { id: "u1", roles: ["admin"] };

		expect(await auth.hasRole(u, "admin")).toBe(true); // from the payload
		expect(await auth.hasRole(u, "auditor")).toBe(true); // from the store
		expect(await auth.hasRole(u, "superadmin")).toBe(false);
	});

	it("hasAllPermissions reflects the resolved set and is vacuously true on []", async () => {
		const store = new MemoryRightsStore().defineRole("editor", [
			"post.edit",
			"post.read",
		]);
		const auth = makeAuth(new RightsResolver(store));
		const u: UserPayload = { id: "u1", roles: ["editor"] };

		expect(await auth.hasAllPermissions(u, ["post.edit", "post.read"])).toBe(
			true,
		);
		expect(await auth.hasAllPermissions(u, ["post.edit", "post.delete"])).toBe(
			false,
		);
		expect(await auth.hasAllPermissions(u, [])).toBe(true);
	});

	it("resolvePermissions returns the EffectivePermissions for (user, scope)", async () => {
		const store = new MemoryRightsStore().grant("u1", "x");
		const auth = makeAuth(new RightsResolver(store));
		const eff = await auth.resolvePermissions({ id: "u1" });

		expect(eff.has("x")).toBe(true);
		expect(eff.scope).toBe("global");
	});

	it("defaults to an empty in-memory store when no resolver is supplied (D4)", async () => {
		// `new AuthManager({ defaultStrategy, strategies })` keeps working —
		// payload roles fold in (D2), permissions resolve empty (D1).
		const auth = makeAuth();
		const u: UserPayload = {
			id: "u1",
			roles: ["admin"],
			permissions: ["post.edit"],
		};

		expect(await auth.hasRole(u, "admin")).toBe(true);
		expect(await auth.hasPermission(u, "post.edit")).toBe(false);
	});

	it("answers the coarse question identically to the policy path (AC5 — one resolver)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("editor", ["post.edit"])
			.assignRole("u1", "editor");
		const resolver = new RightsResolver(store);
		const auth = makeAuth(resolver);
		const u: UserPayload = { id: "u1" };
		const bouncer = new Bouncer(u, {}, {}, { resolver });

		// Seeded permission: coarse helper AND policy both allow.
		const coarseEdit = await auth.hasPermission(u, "post.edit");
		const policyEdit = await bouncer.with(PostPolicy).allows("edit");
		expect(coarseEdit).toBe(true);
		expect(policyEdit).toBe(coarseEdit);

		// Unseeded permission: coarse helper AND policy both deny.
		const coarseDelete = await auth.hasPermission(u, "post.delete");
		const policyDelete = await bouncer.with(PostPolicy).allows("remove");
		expect(coarseDelete).toBe(false);
		expect(policyDelete).toBe(coarseDelete);
	});

	it("does not let a payload role inherit a same-named tenant role through the coarse path (AC6)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("admin", ["global.read"], "global")
			.defineRole("admin", ["acme.secret"], { tenant: "acme" });
		const auth = makeAuth(new RightsResolver(store));
		const u: UserPayload = { id: "u1", roles: ["admin"] };

		// The global admin role's global permission inherits into the tenant scope...
		expect(await auth.hasPermission(u, "global.read", { tenant: "acme" })).toBe(
			true,
		);
		// ...but the same-named tenant admin role's permission is NOT picked up
		// via the token-carried role (no cross-tenant escalation by name).
		expect(await auth.hasPermission(u, "acme.secret", { tenant: "acme" })).toBe(
			false,
		);
	});
});
