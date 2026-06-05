import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { allowGuest } from "../../src/bouncer/decorators.js";
import type { HookResponse } from "../../src/bouncer/types.js";

class Post {
	constructor(readonly authorId: string) {}
}

function user(overrides: Partial<UserPayload> = {}): UserPayload {
	return { id: "u1", ...overrides };
}

class PostPolicy extends BasePolicy {
	edit(current: UserPayload, post: Post): boolean {
		return current.id === post.authorId;
	}

	@allowGuest()
	view(): boolean {
		return true;
	}
}

describe("warden > bouncer > policies", () => {
	it("dispatches the four verbs to the named action method", async () => {
		const post = new Post("u1");
		const owner = new Bouncer(user()).with(PostPolicy);

		expect(await owner.allows("edit", post)).toBe(true);
		expect(await owner.denies("edit", post)).toBe(false);
		expect((await owner.execute("edit", post)).authorized).toBe(true);
		await expect(owner.authorize("edit", post)).resolves.toBeUndefined();

		const stranger = new Bouncer(user({ id: "u2" })).with(PostPolicy);
		expect(await stranger.allows("edit", post)).toBe(false);
		await expect(stranger.authorize("edit", post)).rejects.toMatchObject({
			code: "WARDEN_AUTHORIZATION_FAILURE",
		});
	});

	it("denies a guest on an undecorated method but allows it on an @allowGuest method", async () => {
		const post = new Post("u1");
		const guest = new Bouncer(null).with(PostPolicy);

		expect(await guest.allows("edit", post)).toBe(false);
		expect(await guest.allows("view", post)).toBe(true);
	});

	it("before returning true bypasses a method that would deny — including for a guest", async () => {
		class BypassPolicy extends BasePolicy {
			override before(current: UserPayload | null): HookResponse {
				if (current === null || current.roles?.includes("admin")) {
					return true;
				}
				return undefined;
			}

			secret(): boolean {
				return false;
			}
		}

		// Guest: before short-circuits the guest-deny AND the denying method.
		expect(await new Bouncer(null).with(BypassPolicy).allows("secret")).toBe(
			true,
		);
		// Admin: before bypasses the denying method.
		const admin = new Bouncer(user({ roles: ["admin"] }));
		expect(await admin.with(BypassPolicy).allows("secret")).toBe(true);
		// Plain user: before falls through, method denies.
		expect(await new Bouncer(user()).with(BypassPolicy).allows("secret")).toBe(
			false,
		);
	});

	it("before returning deny('not found', 404) short-circuits with status 404", async () => {
		class NotFoundPolicy extends BasePolicy {
			override before(): HookResponse {
				return AuthorizationResponse.deny("not found", 404);
			}

			edit(): boolean {
				return true;
			}
		}

		const response = await new Bouncer(user())
			.with(NotFoundPolicy)
			.execute("edit");
		expect(response.authorized).toBe(false);
		expect(response.status).toBe(404);
		expect(response.message).toBe("not found");
	});

	it("after returning a deny() overrides an allowing method", async () => {
		class AfterDenyPolicy extends BasePolicy {
			override after(): HookResponse {
				return AuthorizationResponse.deny("blocked");
			}

			edit(): boolean {
				return true;
			}
		}

		const response = await new Bouncer(user())
			.with(AfterDenyPolicy)
			.execute("edit");
		expect(response.authorized).toBe(false);
		expect(response.message).toBe("blocked");
	});

	it("before/after returning undefined leave the method result intact", async () => {
		class PassThroughPolicy extends BasePolicy {
			override before(): HookResponse {
				return undefined;
			}

			override after(): HookResponse {
				return undefined;
			}

			edit(current: UserPayload, post: Post): boolean {
				return current.id === post.authorId;
			}
		}

		const post = new Post("u1");
		expect(
			await new Bouncer(user()).with(PassThroughPolicy).allows("edit", post),
		).toBe(true);
		expect(
			await new Bouncer(user({ id: "u2" }))
				.with(PassThroughPolicy)
				.allows("edit", post),
		).toBe(false);
	});

	it("constructs a fresh policy instance per check (D8)", async () => {
		let constructed = 0;
		class CountingPolicy extends BasePolicy {
			constructor() {
				super();
				constructed += 1;
			}

			edit(): boolean {
				return true;
			}
		}

		const authorizer = new Bouncer(user()).with(CountingPolicy);
		await authorizer.allows("edit");
		await authorizer.allows("edit");
		expect(constructed).toBe(2);
	});

	it("resolves a policy by registered name", async () => {
		const post = new Post("u1");
		const bouncer = new Bouncer(user(), {}, { Post: PostPolicy });
		expect(await bouncer.with("Post").allows("edit", post)).toBe(true);
	});

	it("throws WARDEN_UNKNOWN_POLICY for an unregistered policy name", async () => {
		await expect(
			new Bouncer(user()).with("Ghost").execute("edit"),
		).rejects.toMatchObject({ code: "WARDEN_UNKNOWN_POLICY" });
	});

	it("rejects dispatching to a non-action member (hooks, constructor, inherited)", async () => {
		const authorizer = new Bouncer(user()).with(PostPolicy);
		for (const action of [
			"before",
			"after",
			"constructor",
			"hasOwnProperty",
			"toString",
		]) {
			await expect(authorizer.execute(action)).rejects.toMatchObject({
				code: "WARDEN_UNKNOWN_POLICY_ACTION",
			});
		}
	});

	it("dispatches an action inherited from an intermediate policy base class", async () => {
		class BasePostPolicy extends BasePolicy {
			edit(current: UserPayload, post: Post): boolean {
				return current.id === post.authorId;
			}
		}
		class AuditedPostPolicy extends BasePostPolicy {}

		const post = new Post("u1");
		const owner = new Bouncer(user()).with(AuditedPostPolicy);
		expect(await owner.allows("edit", post)).toBe(true);

		const stranger = new Bouncer(user({ id: "u2" })).with(AuditedPostPolicy);
		expect(await stranger.allows("edit", post)).toBe(false);
	});
});
