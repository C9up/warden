import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import {
	type BouncerRegistry,
	initializeBouncer,
	type WardenContext,
} from "../../src/middleware.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import type { Scope } from "../../src/rights/types.js";

interface Post {
	ownerId: string;
}

const registry: BouncerRegistry = {
	abilities: {
		"post.edit": Bouncer.ability(
			(user, post: Post) => user.id === post.ownerId,
		),
		"page.view": Bouncer.ability({ allowGuest: true }, () => true),
	},
	policies: {},
};

function buildCtx(opts: {
	user?: { id: string };
	registry?: BouncerRegistry;
	resolver?: RightsResolver;
}): { ctx: WardenContext; next: { called: boolean } } {
	// initializeBouncer resolves RightsResolver / "bouncer:registry" from
	// `ctx.containerResolver` (Ream's per-request IoC resolver) — NOT from a
	// `@c9up/ream` import. Wire only what the test provides into a fake resolver;
	// an unbound token throws and the middleware falls back to its defensive
	// path. A fresh resolver per call ⇒ no cross-test leakage.
	const bindings = new Map<unknown, unknown>();
	if (opts.resolver) bindings.set(RightsResolver, opts.resolver);
	if (opts.registry) bindings.set("bouncer:registry", opts.registry);
	const containerResolver: WardenContext["containerResolver"] = {
		async make(token) {
			if (bindings.has(token)) return bindings.get(token);
			throw new Error(`No binding for ${String(token)}`);
		},
	};

	const next = { called: false };
	const ctx: WardenContext = {
		request: { headers: () => ({}) },
		response: { status() {}, json() {} },
		auth: opts.user ? { authenticated: true, user: opts.user } : undefined,
		containerResolver,
	};
	return { ctx, next };
}

describe("warden > initializeBouncer", () => {
	it("attaches a per-request Bouncer and calls next()", async () => {
		const { ctx, next } = buildCtx({ user: { id: "u1" }, registry });
		await initializeBouncer(ctx, () => {
			next.called = true;
		});
		expect(ctx.bouncer).toBeInstanceOf(Bouncer);
		expect(next.called).toBe(true);
	});

	it("authorizes the owner via a registered ability", async () => {
		const { ctx } = buildCtx({ user: { id: "u1" }, registry });
		await initializeBouncer(ctx, () => {});
		expect(await ctx.bouncer?.allows("post.edit", { ownerId: "u1" })).toBe(
			true,
		);
		expect(await ctx.bouncer?.denies("post.edit", { ownerId: "other" })).toBe(
			true,
		);
	});

	it("treats a request with no auth as a guest (user = null)", async () => {
		const { ctx } = buildCtx({ registry });
		await initializeBouncer(ctx, () => {});
		// Guest-allowed ability runs; user-required ability is denied by default.
		expect(await ctx.bouncer?.allows("page.view")).toBe(true);
		expect(await ctx.bouncer?.allows("post.edit", { ownerId: "u1" })).toBe(
			false,
		);
	});

	it("throws WARDEN_AUTHORIZATION_FAILURE (status 403) on authorize denial", async () => {
		const { ctx } = buildCtx({ user: { id: "u2" }, registry });
		await initializeBouncer(ctx, () => {});
		await expect(
			ctx.bouncer?.authorize("post.edit", { ownerId: "u1" }),
		).rejects.toMatchObject({
			code: "WARDEN_AUTHORIZATION_FAILURE",
			status: 403,
		});
	});

	it("honors resolveScope from the registry", async () => {
		const scoped: BouncerRegistry = {
			...registry,
			resolveScope: (): Scope => ({ tenant: "acme" }),
		};
		const { ctx } = buildCtx({ user: { id: "u1" }, registry: scoped });
		await initializeBouncer(ctx, () => {});
		// ctx.bouncer is typed as the agnostic Authorizer slot; narrow to the
		// concrete Bouncer (no cast) to read its `scope`.
		expect(ctx.bouncer).toBeInstanceOf(Bouncer);
		if (ctx.bouncer instanceof Bouncer) {
			expect(ctx.bouncer.scope).toEqual({ tenant: "acme" });
		}
	});

	it("builds an empty Bouncer when the rights layer is not wired", async () => {
		const { ctx, next } = buildCtx({ user: { id: "u1" } });
		await initializeBouncer(ctx, () => {
			next.called = true;
		});
		expect(ctx.bouncer).toBeInstanceOf(Bouncer);
		expect(next.called).toBe(true);
	});

	it("passes a real RightsResolver through to the Bouncer", async () => {
		const resolver = new RightsResolver(new MemoryRightsStore());
		const { ctx } = buildCtx({ user: { id: "u1" }, registry, resolver });
		await initializeBouncer(ctx, () => {});
		expect(ctx.bouncer).toBeInstanceOf(Bouncer);
	});

	// Pinning tests (56.6 code review) — lock the fail-closed security invariants
	// the Epic 54 retro warned about (a fail-open default once passed 138 tests).
	it("never silently allows an unknown ability — it throws (fail-closed)", async () => {
		const { ctx } = buildCtx({ user: { id: "u1" }, registry });
		await initializeBouncer(ctx, () => {});
		await expect(ctx.bouncer?.allows("does.not.exist")).rejects.toMatchObject({
			code: "WARDEN_UNKNOWN_ABILITY",
		});
	});

	it("denies a guest on a non-guest ability via authorize (403)", async () => {
		const { ctx } = buildCtx({ registry });
		await initializeBouncer(ctx, () => {});
		await expect(
			ctx.bouncer?.authorize("post.edit", { ownerId: "u1" }),
		).rejects.toMatchObject({
			code: "WARDEN_AUTHORIZATION_FAILURE",
			status: 403,
		});
	});

	it("fails closed when resolveScope throws — request blocked, no Bouncer", async () => {
		const scoped: BouncerRegistry = {
			...registry,
			resolveScope: (): Scope => {
				throw new Error("scope resolution boom");
			},
		};
		const { ctx, next } = buildCtx({ user: { id: "u1" }, registry: scoped });
		await expect(
			initializeBouncer(ctx, () => {
				next.called = true;
			}),
		).rejects.toThrow();
		expect(next.called).toBe(false);
		expect(ctx.bouncer).toBeUndefined();
	});
});
