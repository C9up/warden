/**
 * Adonis-parity fixes for the Bouncer authorization subsystem: `after` resource
 * args, policy DI via a container resolver, `Bouncer.define`/`AbilitiesBuilder`,
 * `AuthorizationResponse.t`, `deny()` without a default status, a lazy user
 * resolver, and the optional `authorization:finished` event.
 */
import { describe, expect, it, vi } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { AbilitiesBuilder } from "../../src/bouncer/AbilitiesBuilder.js";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import type {
	BouncerEmitter,
	HookResponse,
	PolicyContainerResolver,
} from "../../src/bouncer/types.js";

class Post {
	constructor(readonly authorId: string) {}
}

function user(overrides: Partial<UserPayload> = {}): UserPayload {
	return { id: "u1", ...overrides };
}

describe("warden > bouncer > adonis parity fixes", () => {
	// #7 — after receives the resource args
	it("passes the resource args to the after hook (Adonis after(user, action, result, ...args))", async () => {
		const seen: unknown[] = [];
		class AuditPolicy extends BasePolicy {
			override after(
				_current: UserPayload | null,
				_action: string,
				_result: AuthorizationResponse,
				...args: unknown[]
			): HookResponse {
				seen.push(...args);
				return undefined;
			}

			edit(current: UserPayload, post: Post): boolean {
				return current.id === post.authorId;
			}
		}

		const post = new Post("u1");
		await new Bouncer(user()).with(AuditPolicy).execute("edit", post);
		expect(seen).toEqual([post]);
	});

	it("after can veto based on a resource arg it received", async () => {
		class LockPolicy extends BasePolicy {
			override after(
				_current: UserPayload | null,
				_action: string,
				result: AuthorizationResponse,
				post?: Post,
			): HookResponse {
				return post?.authorId === "locked"
					? AuthorizationResponse.deny("locked")
					: result;
			}

			edit(): boolean {
				return true;
			}
		}

		const authorizer = new Bouncer(user()).with(LockPolicy);
		expect(await authorizer.allows("edit", new Post("u1"))).toBe(true);
		expect(await authorizer.allows("edit", new Post("locked"))).toBe(false);
	});

	// #8 — policy DI via a container resolver
	it("constructs the policy via the container resolver when one is present", async () => {
		class InjectedPolicy extends BasePolicy {
			edit(): boolean {
				return true;
			}
		}

		const seen: Array<new (...args: never[]) => unknown> = [];
		const containerResolver: PolicyContainerResolver = {
			async make<T>(ctor: new (...args: never[]) => T): Promise<T> {
				seen.push(ctor);
				return new ctor();
			},
		};

		const allowed = await new Bouncer(
			user(),
			{},
			{ Post: InjectedPolicy },
			{
				containerResolver,
			},
		)
			.with("Post")
			.allows("edit");

		expect(allowed).toBe(true);
		// The resolver path was taken (a plain `new Policy()` never calls make).
		expect(seen).toEqual([InjectedPolicy]);
	});

	it("falls back to new Policy() when no container resolver is set", async () => {
		let constructed = 0;
		class PlainPolicy extends BasePolicy {
			constructor() {
				super();
				constructed += 1;
			}

			edit(): boolean {
				return true;
			}
		}

		expect(await new Bouncer(user()).with(PlainPolicy).allows("edit")).toBe(
			true,
		);
		expect(constructed).toBe(1);
	});

	// #12a — Bouncer.define + AbilitiesBuilder
	it("Bouncer.define returns a chainable AbilitiesBuilder with an .abilities map", async () => {
		const builder = Bouncer.define(
			"editPost",
			(current: UserPayload, post: Post) => current.id === post.authorId,
		).define("viewPost", () => true, { allowGuest: true });

		expect(builder).toBeInstanceOf(AbilitiesBuilder);
		expect(Object.keys(builder.abilities).sort()).toEqual([
			"editPost",
			"viewPost",
		]);

		const bouncer = new Bouncer(user(), builder.abilities);
		expect(await bouncer.allows("editPost", new Post("u1"))).toBe(true);
		expect(await bouncer.allows("editPost", new Post("u2"))).toBe(false);
		// viewPost was defined with allowGuest, so a guest reaches the callback.
		expect(await new Bouncer(null, builder.abilities).allows("viewPost")).toBe(
			true,
		);
	});

	// #12b — AuthorizationResponse.t()
	it("AuthorizationResponse.t sets the translation binding and returns this", () => {
		const response = AuthorizationResponse.deny("nope");
		const returned = response.t("errors.forbidden", { resource: "post" });
		expect(returned).toBe(response);
		expect(response.translation).toEqual({
			identifier: "errors.forbidden",
			data: { resource: "post" },
		});
	});

	// #12c — deny() with no default status
	it("deny() leaves status undefined but the thrown failure still maps to 403", async () => {
		expect(AuthorizationResponse.deny().status).toBeUndefined();

		let thrown: unknown;
		try {
			await new Bouncer(user()).authorize(Bouncer.ability(() => false));
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toMatchObject({
			code: "E_WARDEN_AUTHORIZATION_FAILURE",
			status: 403,
		});
	});

	// #12d — lazy user resolver
	it("accepts a lazy user resolver and invokes it at most once", async () => {
		const resolver = vi.fn((): UserPayload | null => user());
		const bouncer = new Bouncer(resolver);
		const ability = Bouncer.ability((current) => current.id === "u1");

		expect(await bouncer.allows(ability)).toBe(true);
		expect(await bouncer.allows(ability)).toBe(true);
		expect(resolver).toHaveBeenCalledTimes(1);
	});

	it("a lazy resolver returning null denies a guest-denied ability", async () => {
		const bouncer = new Bouncer((): UserPayload | null => null);
		expect(await bouncer.allows(Bouncer.ability(() => true))).toBe(false);
	});

	// #12e — optional authorization:finished event
	it("emits authorization:finished after an ability evaluation with { user, action, parameters, response }", async () => {
		const emit = vi.fn();
		const emitter: BouncerEmitter = { emit };
		const currentUser = user();
		const bouncer = new Bouncer(currentUser, {}, {}, { emitter });

		const response = await bouncer.execute(Bouncer.ability(() => true));

		expect(emit).toHaveBeenCalledTimes(1);
		expect(emit).toHaveBeenCalledWith("authorization:finished", {
			user: currentUser,
			action: "(ability)",
			parameters: [],
			response,
		});
	});

	it("carries what the check was about", async () => {
		const emit = vi.fn();
		const currentUser = user();
		const post = { id: 7 };
		const bouncer = new Bouncer(currentUser, {}, {}, { emitter: { emit } });

		await bouncer.execute(
			Bouncer.ability((_u: UserPayload, _p: { id: number }) => false),
			post,
		);

		// Without the arguments an audit log can say "Ada was denied editPost"
		// but never which post — which is most of what an audit is for.
		expect(emit).toHaveBeenCalledWith(
			"authorization:finished",
			expect.objectContaining({ parameters: [post] }),
		);
	});

	it("emits authorization:finished after a policy evaluation", async () => {
		const emit = vi.fn();
		class ThingPolicy extends BasePolicy {
			update(): boolean {
				return true;
			}
		}
		const currentUser = user();
		await new Bouncer(currentUser, {}, {}, { emitter: { emit } })
			.with(ThingPolicy)
			.execute("update");

		expect(emit).toHaveBeenCalledTimes(1);
		expect(emit).toHaveBeenCalledWith(
			"authorization:finished",
			expect.objectContaining({
				user: currentUser,
				action: "update",
				parameters: [],
			}),
		);
	});

	it("is a no-op when no emitter is configured", async () => {
		await expect(
			new Bouncer(user()).allows(Bouncer.ability(() => true)),
		).resolves.toBe(true);
	});
});

describe("warden > Bouncer.responseBuilder (AdonisJS parity)", () => {
	it("turns every bare boolean into the house response", async () => {
		const original = Bouncer.responseBuilder;
		try {
			// Replace it once at boot and every `return false` gets a message and
			// a status instead of a naked 403.
			Bouncer.responseBuilder = (value) =>
				value === false
					? AuthorizationResponse.deny("Nothing here", 404)
					: original(value);

			const bouncer = new Bouncer(user());
			const response = await bouncer.execute(Bouncer.ability(() => false));

			expect(response.authorized).toBe(false);
			expect(response.status).toBe(404);
			expect(response.message).toBe("Nothing here");
		} finally {
			Bouncer.responseBuilder = original;
		}
	});

	it("leaves an explicit response alone", async () => {
		const bouncer = new Bouncer(user());
		const response = await bouncer.execute(
			Bouncer.ability(() => AuthorizationResponse.deny("Explicit", 418)),
		);

		expect(response.status).toBe(418);
	});

	it("reaches a policy too", async () => {
		const original = Bouncer.responseBuilder;
		try {
			Bouncer.responseBuilder = (value) =>
				value === false
					? AuthorizationResponse.deny("Policy denied", 451)
					: original(value);

			class ThingPolicy extends BasePolicy {
				update(): boolean {
					return false;
				}
			}
			const response = await new Bouncer(user())
				.with(ThingPolicy)
				.execute("update");

			expect(response.status).toBe(451);
		} finally {
			Bouncer.responseBuilder = original;
		}
	});
});

describe("warden > PolicyAuthorizer.setEmitter (AdonisJS parity)", () => {
	it("takes an emitter after construction", async () => {
		const emit = vi.fn();
		class ThingPolicy extends BasePolicy {
			update(): boolean {
				return true;
			}
		}
		// An authorizer built directly — a test, a console command — had no way
		// to be given one.
		const authorizer = new Bouncer(user()).with(ThingPolicy);
		expect(authorizer.setEmitter({ emit })).toBe(authorizer);

		await authorizer.execute("update");
		expect(emit).toHaveBeenCalledWith(
			"authorization:finished",
			expect.objectContaining({ action: "update" }),
		);
	});
});

describe("bouncer > an Adonis-shaped emitter whose listener rejects", () => {
	it("still returns the decision, and reports rather than ending the process", async () => {
		// `@adonisjs/events` declares `emit(): Promise<void>` and rethrows when a
		// listener fails and no error handler is registered. An authorization
		// event is an audit trail, not a participant in the decision — nobody
		// awaits it — so that rejection had nowhere to go. The interface said
		// `void`, which accepts a promise-returning function, so the call site
		// read as if there were nothing to handle.
		const written: string[] = [];
		const rejections: unknown[] = [];
		const originalWrite = process.stderr.write.bind(process.stderr);
		const onUnhandled = (reason: unknown): void => {
			rejections.push(reason);
		};
		process.stderr.write = (chunk: string | Uint8Array): boolean => {
			written.push(String(chunk));
			return true;
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			const emitter = {
				emit: async () => {
					throw new Error("the audit logger blew up");
				},
			};
			const bouncer = new Bouncer(
				{ id: "u1" },
				{ editPost: Bouncer.ability(() => true) },
				undefined,
				{ emitter },
			);

			// The decision itself must be unaffected.
			expect(await bouncer.allows("editPost")).toBe(true);
			await new Promise((resolve) => setTimeout(resolve, 15));

			expect(rejections).toEqual([]);
			expect(written.join("")).toContain("audit logger blew up");
		} finally {
			process.stderr.write = originalWrite;
			process.off("unhandledRejection", onUnhandled);
		}
	});
});
