import { describe, expect, it } from "vitest";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";

describe("warden > MemoryRightsStore", () => {
	it("seeds and reads back role permissions in scope", async () => {
		const store = new MemoryRightsStore().defineRole("editor", [
			"post.edit",
			"post.view",
		]);
		expect(
			[...(await store.rolePermissions("editor", "global"))].sort(),
		).toEqual(["post.edit", "post.view"]);
	});

	it("returns [] for an unknown role, user, or grant (fail-closed reads)", async () => {
		const store = new MemoryRightsStore();
		expect(await store.rolePermissions("ghost", "global")).toEqual([]);
		expect(await store.userRoles("nobody", "global")).toEqual([]);
		expect(await store.userGrants("nobody", "global")).toEqual([]);
	});

	it("redefining a role replaces its permission set", async () => {
		const store = new MemoryRightsStore()
			.defineRole("editor", ["post.edit"])
			.defineRole("editor", ["post.view"]);
		expect(await store.rolePermissions("editor", "global")).toEqual([
			"post.view",
		]);
	});

	it("assignRole and grant accumulate, revoke removes a single grant", async () => {
		const store = new MemoryRightsStore()
			.assignRole("u1", "editor")
			.assignRole("u1", "viewer")
			.grant("u1", "post.delete")
			.grant("u1", "post.archive");

		expect([...(await store.userRoles("u1", "global"))].sort()).toEqual([
			"editor",
			"viewer",
		]);

		store.revoke("u1", "post.delete");
		expect(await store.userGrants("u1", "global")).toEqual(["post.archive"]);
	});

	it("returns a fresh defensive copy on every read (no live internal reference)", async () => {
		const store = new MemoryRightsStore().defineRole("editor", ["post.edit"]);
		const first = await store.rolePermissions("editor", "global");
		const second = await store.rolePermissions("editor", "global");

		// Distinct instances per call: callers never hold the store's internals,
		// so mutating a returned array cannot corrupt subsequent reads.
		expect(first).not.toBe(second);
		expect(first).toEqual(second);
		expect(first).toEqual(["post.edit"]);
	});

	it("keys storage by scope — global and tenant rights stay isolated", async () => {
		const store = new MemoryRightsStore()
			.grant("u1", "global.perm", "global")
			.grant("u1", "acme.perm", { tenant: "acme" });

		expect(await store.userGrants("u1", "global")).toEqual(["global.perm"]);
		expect(await store.userGrants("u1", { tenant: "acme" })).toEqual([
			"acme.perm",
		]);
		expect(await store.userGrants("u1", { tenant: "other" })).toEqual([]);
	});

	it("seeding methods are chainable and default to global scope", async () => {
		const store = new MemoryRightsStore();
		const result = store.defineRole("r", ["p"]).assignRole("u1", "r");
		expect(result).toBe(store);
		expect(await store.userRoles("u1", "global")).toEqual(["r"]);
	});
});
