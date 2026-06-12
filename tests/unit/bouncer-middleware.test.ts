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
	const next = { called: false };
	const ctx: WardenContext = {
		request: { method: "GET", url: "/", headers: {} },
		response: { status() {}, json() {} },
		container: {
			resolve(token) {
				if (token === RightsResolver) {
					if (opts.resolver) return opts.resolver;
					throw new Error("no resolver");
				}
				if (token === "bouncer:registry") {
					if (opts.registry) return opts.registry;
					throw new Error("no registry");
				}
				throw new Error(`unexpected token: ${String(token)}`);
			},
		},
		auth: opts.user ? { authenticated: true, user: opts.user } : undefined,
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
		expect(ctx.bouncer?.scope).toEqual({ tenant: "acme" });
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
});
