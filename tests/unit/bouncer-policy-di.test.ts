/**
 * Policy dependency injection through the request resolver.
 *
 * `Bouncer` has been able to construct a policy through an IoC resolver from
 * the start — but `initializeBouncer` never passed `ctx.containerResolver`, so
 * a policy declaring constructor dependencies was always built with a plain
 * `new Policy()` and got none of them. The plumbing existed and was not
 * connected to anything.
 */

import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { initializeBouncer, type WardenContext } from "../../src/middleware.js";

class Clock {
	now(): string {
		return "2026-08-24";
	}
}

class PostPolicy extends BasePolicy {
	constructor(readonly clock: Clock = new Clock()) {
		super();
	}
	view(): boolean {
		return this.clock.now() === "injected";
	}
}

/** A resolver that builds PostPolicy with a Clock the test controls. */
function resolverFor(clock: Clock): WardenContext["containerResolver"] {
	return {
		async make(token) {
			// The middleware asks the container for its registry first.
			if (token === "bouncer:registry")
				return { abilities: {}, policies: { PostPolicy } };
			if (token === PostPolicy) return new PostPolicy(clock);
			throw new Error(`No binding for ${String(token)}`);
		},
	};
}

/** A resolver that always builds PostPolicy with the injected clock. */
function fixedClockResolver(): { make<T>(ctor: new () => T): Promise<T> } {
	return {
		async make<T>(ctor: new () => T): Promise<T> {
			const instance = new PostPolicy(new FixedClock());
			if (!(instance instanceof ctor)) {
				throw new Error("the fake resolver was asked for another class");
			}
			return instance;
		},
	};
}

class FixedClock extends Clock {
	override now(): string {
		return "injected";
	}
}

function ctxWith(
	containerResolver: WardenContext["containerResolver"],
): WardenContext {
	return {
		request: { headers: () => ({}) },
		response: { status() {}, json() {} },
		containerResolver,
		// A signed-in user: the bouncer denies a guest before it ever builds a
		// policy, so guest would hide whether the injection happened.
		auth: { user: { id: "1" } },
	};
}

describe("warden > policy DI through the request resolver", () => {
	it("builds a policy through the container the request carries", async () => {
		const ctx = ctxWith(resolverFor(new FixedClock()));
		await initializeBouncer(ctx, async () => {});

		// The bouncer the middleware seated must construct through the resolver.
		const bouncer = ctx.bouncer as Bouncer;
		expect(await bouncer.with("PostPolicy").allows("view")).toBe(true);
	});

	it("gets whatever the container builds, dependencies and all", async () => {
		// A real container auto-constructs an unbound class, so an unbound policy
		// comes back with its own defaults rather than the injected clock.
		const ctx = ctxWith({
			async make(token) {
				if (token === "bouncer:registry")
					return { abilities: {}, policies: { PostPolicy } };
				if (typeof token === "function") return new PostPolicy();
				throw new Error(`No binding for ${String(token)}`);
			},
		});
		await initializeBouncer(ctx, async () => {});

		const bouncer = ctx.bouncer as Bouncer;
		// No resolver: `new PostPolicy()` with its default Clock, which says no.
		expect(await bouncer.with("PostPolicy").allows("view")).toBe(false);
	});

	it("refuses an instance the container resolved to something else", async () => {
		// A host resolver handing back the wrong object must not reach the
		// policy's methods.
		const ctx = ctxWith({
			async make(token) {
				if (token === "bouncer:registry")
					return { abilities: {}, policies: { PostPolicy } };
				return { view: () => true };
			},
		});
		await initializeBouncer(ctx, async () => {});

		const bouncer = ctx.bouncer as Bouncer;
		await expect(bouncer.with("PostPolicy").allows("view")).rejects.toThrow(
			/must be an instance of the class/,
		);
	});

	it("setContainerResolver swaps the resolver after construction", async () => {
		const bouncer = new Bouncer({ id: "1" }, {}, { PostPolicy });

		expect(await bouncer.with("PostPolicy").allows("view")).toBe(false);

		bouncer.setContainerResolver(fixedClockResolver());

		expect(await bouncer.with("PostPolicy").allows("view")).toBe(true);
	});

	it("setContainerResolver(undefined) goes back to a plain instance", async () => {
		const bouncer = new Bouncer({ id: "1" }, {}, { PostPolicy });
		bouncer.setContainerResolver(fixedClockResolver());
		expect(await bouncer.with("PostPolicy").allows("view")).toBe(true);

		bouncer.setContainerResolver(undefined);

		expect(await bouncer.with("PostPolicy").allows("view")).toBe(false);
	});
});
