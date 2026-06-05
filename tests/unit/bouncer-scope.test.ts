import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import type { EffectivePermissions, Scope } from "../../src/rights/types.js";

function user(overrides: Partial<UserPayload> = {}): UserPayload {
	return { id: "u1", ...overrides };
}

/** Counts how many times `resolve()` runs — proves the per-Bouncer memo (D3). */
class CountingResolver extends RightsResolver {
	calls = 0;
	override resolve(
		payload: UserPayload,
		scope?: Scope,
	): Promise<EffectivePermissions> {
		this.calls += 1;
		return super.resolve(payload, scope);
	}
}

/** Captures the scope + resolved permissions a policy sees for one check. */
let captured: { scope: Scope; permissions: EffectivePermissions } | undefined;
class CapturePolicy extends BasePolicy {
	inspect(): boolean {
		captured = { scope: this.scope, permissions: this.permissions };
		return true;
	}
}

/** Enforces tenant isolation explicitly (D5) via the `sameTenant` helper. */
class PostPolicy extends BasePolicy {
	edit(_current: UserPayload, post: { tenantId?: string | null }): boolean {
		return this.sameTenant(post);
	}
}

describe("warden > bouncer > scope (56.3)", () => {
	it("defaults to the global scope with empty permissions when given no context", async () => {
		const bouncer = new Bouncer(user());
		expect(bouncer.scope).toBe("global");

		captured = undefined;
		await bouncer.with(CapturePolicy).allows("inspect");
		expect(captured?.scope).toBe("global");
		expect(captured?.permissions.permissions.size).toBe(0);
		expect(captured?.permissions.roles.size).toBe(0);
		expect(captured?.permissions.has("anything")).toBe(false);
		expect(captured?.permissions.hasAll([])).toBe(true);
		expect(captured?.permissions.hasAny(["x"])).toBe(false);
		expect(captured?.permissions.scope).toBe("global");
	});

	it("reads global/empty defaults on a policy used without a Bouncer (AC2)", () => {
		captured = undefined;
		expect(new CapturePolicy().inspect()).toBe(true);
		expect(captured?.scope).toBe("global");
		expect(captured?.permissions.permissions.size).toBe(0);
	});

	it("resolves tenant + inherited global permissions through the policy path (AC3)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("admin", ["tenant.manage"], "global")
			.assignRole("u1", "admin", "global")
			.grant("u1", "post.publish", { tenant: "acme" });
		const bouncer = new Bouncer(user(), {}, {}, {
			scope: { tenant: "acme" },
			resolver: new RightsResolver(store),
		});

		captured = undefined;
		await bouncer.with(CapturePolicy).allows("inspect");
		expect(captured?.scope).toEqual({ tenant: "acme" });
		// tenant-scoped grant
		expect(captured?.permissions.has("post.publish")).toBe(true);
		// inherited global role permission
		expect(captured?.permissions.has("tenant.manage")).toBe(true);
		expect(captured?.permissions.scope).toEqual({ tenant: "acme" });
	});

	it("memoizes resolution once per Bouncer across N checks (D3)", async () => {
		const store = new MemoryRightsStore().grant("u1", "x", {
			tenant: "acme",
		});
		const resolver = new CountingResolver(store);
		const bouncer = new Bouncer(user(), {}, {}, {
			scope: { tenant: "acme" },
			resolver,
		});

		await bouncer.with(CapturePolicy).allows("inspect");
		await bouncer.with(CapturePolicy).allows("inspect");
		await bouncer.with(CapturePolicy).allows("inspect");
		expect(resolver.calls).toBe(1);
	});

	it("never resolves for a guest and yields empty permissions (D9)", async () => {
		const resolver = new CountingResolver(new MemoryRightsStore());
		const bouncer = new Bouncer(null, {}, {}, {
			scope: { tenant: "acme" },
			resolver,
		});

		captured = undefined;
		// A guest is denied the (undecorated) action, but `before` short-circuit is
		// irrelevant here — we assert the resolver is never consulted for a null user.
		await bouncer.with(CapturePolicy).allows("inspect");
		expect(resolver.calls).toBe(0);
	});

	it("yields empty permissions when no resolver is configured", async () => {
		const bouncer = new Bouncer(user(), {}, {}, { scope: { tenant: "acme" } });
		captured = undefined;
		await bouncer.with(CapturePolicy).allows("inspect");
		expect(captured?.permissions.permissions.size).toBe(0);
		expect(captured?.scope).toEqual({ tenant: "acme" });
	});

	it("enforces tenant isolation via sameTenant (AC4)", async () => {
		const tenantBouncer = new Bouncer(user(), {}, {}, {
			scope: { tenant: "acme" },
		});
		const acmePost = { tenantId: "acme" };
		const otherPost = { tenantId: "beta" };

		expect(await tenantBouncer.with(PostPolicy).allows("edit", acmePost)).toBe(
			true,
		);
		expect(await tenantBouncer.with(PostPolicy).allows("edit", otherPost)).toBe(
			false,
		);

		// Under global scope, isolation is a no-op — every resource passes.
		const globalBouncer = new Bouncer(user());
		expect(await globalBouncer.with(PostPolicy).allows("edit", otherPost)).toBe(
			true,
		);
	});

	it("treats a resource missing tenantId as cross-tenant under a tenant scope (AC4)", async () => {
		const tenantBouncer = new Bouncer(user(), {}, {}, {
			scope: { tenant: "acme" },
		});
		// `undefined !== "acme"` ⇒ denied (no accidental allow on a missing id).
		expect(await tenantBouncer.with(PostPolicy).allows("edit", {})).toBe(false);
	});

	it("does not let a payload role inherit a same-named tenant role (AC8 guard)", async () => {
		const store = new MemoryRightsStore()
			.defineRole("admin", ["global.read"], "global")
			.defineRole("admin", ["acme.secret"], { tenant: "acme" });
		const bouncer = new Bouncer(user({ roles: ["admin"] }), {}, {}, {
			scope: { tenant: "acme" },
			resolver: new RightsResolver(store),
		});

		captured = undefined;
		await bouncer.with(CapturePolicy).allows("inspect");
		// The global admin role's global permission inherits...
		expect(captured?.permissions.has("global.read")).toBe(true);
		// ...but the same-named tenant role's permission is NOT picked up.
		expect(captured?.permissions.has("acme.secret")).toBe(false);
		expect(captured?.permissions.roles.has("admin")).toBe(true);
	});

	it("keeps the 56.2 four-verb behaviour intact under the default scope (parity)", async () => {
		const post = { tenantId: "acme" };
		const owner = new Bouncer(user()).with(PostPolicy);
		// global scope ⇒ sameTenant always true ⇒ every verb agrees, signatures unchanged.
		expect(await owner.allows("edit", post)).toBe(true);
		expect(await owner.denies("edit", post)).toBe(false);
		expect((await owner.execute("edit", post)).authorized).toBe(true);
		await expect(owner.authorize("edit", post)).resolves.toBeUndefined();
	});
});
