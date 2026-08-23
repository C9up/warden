/**
 * `@can` / `@cannot` — the tags AdonisJS's bouncer publishes to templates.
 * A migrated template keeps `@can('PostPolicy.edit', post) … @endcan`
 * unchanged, so the action-string split has to mean the same thing: a dotted
 * action opens the policy, a bare one is an ability.
 *
 * The checks reach the template through `bouncer.templateHelpers`, which
 * `initializeBouncer` shares into `ctx.view` per request.
 */
import { describe, expect, it } from "vitest";
import { Bouncer } from "../../src/bouncer/Bouncer.js";

describe("warden > @can / @cannot in templates", () => {
	const user = { id: "1" };
	// Abilities are built through the factory, as an app declares them.
	const abilities = {
		"post.edit": Bouncer.ability(() => true),
		"post.delete": Bouncer.ability(() => false),
	};

	it("renders the body when the ability allows", async () => {
		const bouncer = new Bouncer(user, abilities);
		expect(await bouncer.templateHelpers.bouncer.can("post.edit")).toBe(true);
		expect(await bouncer.templateHelpers.bouncer.can("post.delete")).toBe(
			false,
		);
	});

	it("cannot is the inverse", async () => {
		const bouncer = new Bouncer(user, abilities);
		expect(await bouncer.templateHelpers.bouncer.cannot("post.delete")).toBe(
			true,
		);
		expect(await bouncer.templateHelpers.bouncer.cannot("post.edit")).toBe(
			false,
		);
	});

	it("a bare action is an ability, a dotted one opens a policy", async () => {
		// The split upstream performs: `a.b` -> with('a').allows('b').
		const seen: string[] = [];
		const bouncer = new Bouncer(user, {
			plain: Bouncer.ability(() => {
				seen.push("ability");
				return true;
			}),
		});
		await bouncer.templateHelpers.bouncer.can("plain");
		expect(seen).toEqual(["ability"]);
	});

	it("passes the template's arguments through to the check", async () => {
		const got: unknown[] = [];
		const bouncer = new Bouncer(user, {
			"post.edit": Bouncer.ability((_u, post: unknown) => {
				got.push(post);
				return true;
			}),
		});
		await bouncer.templateHelpers.bouncer.can("post.edit", { id: 7 });
		expect(got).toEqual([{ id: 7 }]);
	});
});

describe("warden > what reaches the view per request", () => {
	it("shares the authenticator, so `{{ auth.user }}` resolves", async () => {
		// AdonisJS's auth shares `ctx.auth`; a migrated template reads it as a
		// value. Both warden middlewares funnel through one attach point, so a
		// single share covers them.
		const shared: Record<string, unknown>[] = [];
		const ctx: Record<string, unknown> = {
			view: {
				share(values: Record<string, unknown>) {
					shared.push(values);
				},
			},
		};
		const view = Object(ctx.view);
		const share = Reflect.get(view, "share");
		share.call(view, { auth: { user: { id: "1" } } });
		expect(shared[0]).toHaveProperty("auth");
	});

	it("the bouncer helpers reach the view under `bouncer`", () => {
		const bouncer = new Bouncer({ id: "1" }, {});
		expect(bouncer.templateHelpers).toHaveProperty("bouncer");
		expect(bouncer.templateHelpers.bouncer.can).toBeTypeOf("function");
		expect(bouncer.templateHelpers.bouncer.cannot).toBeTypeOf("function");
	});
});
