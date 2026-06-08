import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";

function user(overrides: Partial<UserPayload> = {}): UserPayload {
	return { id: "u1", ...overrides };
}

describe("warden > RightsResolver", () => {
	it("merges role-derived permissions with direct grants (D3+D4)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("editor", ["post.edit", "post.view"])
			.assignRole("u1", "editor")
			.grant("u1", "post.delete");
		const eff = await new RightsResolver(store).resolve(user());

		expect(eff.has("post.edit")).toBe(true);
		expect(eff.has("post.view")).toBe(true);
		expect(eff.has("post.delete")).toBe(true);
		expect(eff.has("post.publish")).toBe(false);
		expect([...eff.permissions].sort()).toEqual([
			"post.delete",
			"post.edit",
			"post.view",
		]);
	});

	it("unions roles carried on the payload with roles assigned in the store (D3)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("editor", ["post.edit"])
			.defineRole("viewer", ["post.view"])
			.assignRole("u1", "viewer");
		// `editor` arrives via the token payload, `viewer` via the store.
		const eff = await new RightsResolver(store).resolve(
			user({ roles: ["editor"] }),
		);

		expect([...eff.roles].sort()).toEqual(["editor", "viewer"]);
		expect(eff.hasAll(["post.edit", "post.view"])).toBe(true);
	});

	it("ignores payload permissions — they are not a resolver input (D4)", async () => {
		const store = new MemoryRightsStore();
		const eff = await new RightsResolver(store).resolve(
			user({ permissions: ["secret.access"] }),
		);

		expect(eff.has("secret.access")).toBe(false);
		expect(eff.permissions.size).toBe(0);
	});

	it("inherits global-scope rights into every tenant scope (D5)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("admin", ["tenant.manage"], "global")
			.assignRole("u1", "admin", "global");
		const eff = await new RightsResolver(store).resolve(user(), {
			tenant: "acme",
		});

		expect(eff.has("tenant.manage")).toBe(true);
		expect(eff.roles.has("admin")).toBe(true);
	});

	it("does not let a payload role inherit a same-named tenant role's permissions (D5)", async () => {
		// `admin` is defined only as a tenant-scoped role; the user carries `admin`
		// on the token but was never assigned it inside the tenant.
		const store = new MemoryRightsStore().defineRole(
			"admin",
			["acme.billing.delete"],
			{ tenant: "acme" },
		);
		const eff = await new RightsResolver(store).resolve(
			user({ roles: ["admin"] }),
			{ tenant: "acme" },
		);

		// The role still surfaces as identity, but the tenant role's permissions
		// are NOT granted — token roles are global identity, not a tenant grant.
		expect(eff.roles.has("admin")).toBe(true);
		expect(eff.has("acme.billing.delete")).toBe(false);
	});

	it("still grants a payload role's GLOBAL permissions inside a tenant scope (D5)", async () => {
		const store = new MemoryRightsStore().defineRole(
			"superadmin",
			["system.manage"],
			"global",
		);
		const eff = await new RightsResolver(store).resolve(
			user({ roles: ["superadmin"] }),
			{ tenant: "acme" },
		);

		expect(eff.has("system.manage")).toBe(true);
	});

	it("does not leak tenant-scoped rights across tenants or into global (D5)", async () => {
		const store = new MemoryRightsStore().grant("u1", "acme.secret", {
			tenant: "acme",
		});
		const resolver = new RightsResolver(store);

		const inAcme = await resolver.resolve(user(), { tenant: "acme" });
		const inOther = await resolver.resolve(user(), { tenant: "other" });
		const inGlobal = await resolver.resolve(user());

		expect(inAcme.has("acme.secret")).toBe(true);
		expect(inOther.has("acme.secret")).toBe(false);
		expect(inGlobal.has("acme.secret")).toBe(false);
	});

	it("fails closed on an unknown role — no permissions, no throw (D6)", async () => {
		const store = new MemoryRightsStore().assignRole("u1", "ghost");
		const eff = await new RightsResolver(store).resolve(user());

		expect(eff.roles.has("ghost")).toBe(true);
		expect(eff.permissions.size).toBe(0);
		expect(eff.has("anything")).toBe(false);
	});

	it("resolves an empty user to empty sets (D6)", async () => {
		const eff = await new RightsResolver(new MemoryRightsStore()).resolve(
			user(),
		);

		expect(eff.permissions.size).toBe(0);
		expect(eff.roles.size).toBe(0);
		expect(eff.has("x")).toBe(false);
	});

	it("applies vacuous-truth semantics for hasAll/hasAny on empty lists (D8)", async () => {
		const eff = await new RightsResolver(new MemoryRightsStore()).resolve(
			user(),
		);

		expect(eff.hasAll([])).toBe(true);
		expect(eff.hasAny([])).toBe(false);
	});

	it("defaults the scope to global when omitted (D1)", async () => {
		const eff = await new RightsResolver(new MemoryRightsStore()).resolve(
			user(),
		);

		expect(eff.scope).toBe("global");
	});
});
