/**
 * AC-E2 parity gate — pins the AdonisJS Bouncer contract (verified context7
 * `/adonisjs/bouncer`, 2026-06-01) so a later refactor cannot silently drift the
 * shape. Each test encodes one facet of the canonical contract.
 */
import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { action, allowGuest } from "../../src/bouncer/decorators.js";
import type { HookResponse } from "../../src/bouncer/types.js";

const owner: UserPayload = { id: "owner" };

describe("warden > bouncer > parity (AC-E2)", () => {
	it("Bouncer.ability has two overloads: guest-denied default and { allowGuest }", async () => {
		const guestDenied = Bouncer.ability((current) => current.id === "owner");
		const guestAllowed = Bouncer.ability(
			{ allowGuest: true },
			(current) => current === null,
		);

		expect(await new Bouncer(owner).allows(guestDenied)).toBe(true);
		expect(await new Bouncer(null).allows(guestDenied)).toBe(false);
		expect(await new Bouncer(null).allows(guestAllowed)).toBe(true);
	});

	it("AuthorizationResponse.deny carries no status unless passed; allow() carries no status", () => {
		expect(AuthorizationResponse.deny().status).toBeUndefined();
		expect(AuthorizationResponse.deny("m", 404).status).toBe(404);
		expect(AuthorizationResponse.allow().status).toBeUndefined();
	});

	it("the four verbs behave as Adonis defines them", async () => {
		const bouncer = new Bouncer(owner);
		const allow = Bouncer.ability(() => true);
		const deny = Bouncer.ability(() => false);

		expect(await bouncer.allows(allow)).toBe(true);
		expect(await bouncer.denies(deny)).toBe(true);
		expect((await bouncer.execute(deny)).authorized).toBe(false);
		await expect(bouncer.authorize(allow)).resolves.toBeUndefined();
		await expect(bouncer.authorize(deny)).rejects.toMatchObject({
			code: "WARDEN_AUTHORIZATION_FAILURE",
		});
	});

	it("bouncer.with(Policy) exposes the same four verbs", async () => {
		class ThingPolicy extends BasePolicy {
			update(): boolean {
				return true;
			}
		}
		const authorizer = new Bouncer(owner).with(ThingPolicy);

		expect(await authorizer.allows("update")).toBe(true);
		expect(await authorizer.denies("update")).toBe(false);
		expect((await authorizer.execute("update")).authorized).toBe(true);
		await expect(authorizer.authorize("update")).resolves.toBeUndefined();
	});

	it("@allowGuest() is equivalent to @action({ allowGuest: true })", async () => {
		class DecoratedPolicy extends BasePolicy {
			@allowGuest()
			viaAllowGuest(): boolean {
				return true;
			}

			@action({ allowGuest: true })
			viaAction(): boolean {
				return true;
			}

			undecorated(): boolean {
				return true;
			}
		}
		const guest = new Bouncer(null).with(DecoratedPolicy);

		expect(await guest.allows("viaAllowGuest")).toBe(true);
		expect(await guest.allows("viaAction")).toBe(true);
		expect(await guest.allows("undecorated")).toBe(false);
	});

	it("evaluation order is before -> guest-deny -> action -> after (D5)", async () => {
		const trace: string[] = [];
		class OrderPolicy extends BasePolicy {
			override before(): HookResponse {
				trace.push("before");
				return undefined;
			}

			override after(
				_current: UserPayload | null,
				_name: string,
				result: AuthorizationResponse,
			): HookResponse {
				trace.push("after");
				return result;
			}

			act(): boolean {
				trace.push("action");
				return true;
			}
		}

		await new Bouncer(owner).with(OrderPolicy).execute("act");
		expect(trace).toEqual(["before", "action", "after"]);

		// Guest on an undecorated method: before runs, action is skipped, after still runs.
		trace.length = 0;
		await new Bouncer(null).with(OrderPolicy).execute("act");
		expect(trace).toEqual(["before", "after"]);
	});

	it("an async ability callback is awaited for both allow and deny", async () => {
		// context7 `/adonisjs/bouncer` (re-verified 2026-06-12):
		// `Bouncer.ability(async (user, post) => …)` — a predicate may be async
		// (e.g. a DB-backed check) and is awaited before the verdict is read.
		const asyncAllow = Bouncer.ability(
			async (current) => current.id === "owner",
		);
		const asyncDeny = Bouncer.ability(async () =>
			AuthorizationResponse.deny("async nope", 409),
		);

		expect(await new Bouncer(owner).allows(asyncAllow)).toBe(true);
		// A non-owner must be DENIED — this is the assertion that actually bites a
		// missing `await`: an unawaited Promise is truthy, so without the await this
		// would wrongly allow the intruder.
		expect(await new Bouncer({ id: "intruder" }).allows(asyncAllow)).toBe(
			false,
		);
		const denied = await new Bouncer(owner).execute(asyncDeny);
		expect(denied.authorized).toBe(false);
		expect(denied.status).toBe(409);
		expect(denied.message).toBe("async nope");
	});

	it("allowGuest runs the callback for a guest but the predicate still decides", async () => {
		// context7 `/adonisjs/bouncer` (re-verified 2026-06-12):
		// `@allowGuest view(user, post) { return post.isPublished }` — allowGuest
		// bypasses the guest-deny GATE, it is NOT an auto-allow; the callback's
		// verdict stands, so a guest passes only when the predicate is true.
		const viewable = Bouncer.ability(
			{ allowGuest: true },
			(_current, isPublished: boolean) => isPublished,
		);

		expect(await new Bouncer(null).allows(viewable, true)).toBe(true);
		expect(await new Bouncer(null).allows(viewable, false)).toBe(false);
	});

	it("after overrides a before short-circuit — the action is skipped, after wins", async () => {
		// context7 `/adonisjs/bouncer` (re-verified 2026-06-12): before short-
		// circuits the action with a non-undefined return; after still runs and may
		// override that result. Here before allows, the action never runs, and after
		// flips it to a deny — after has the last word over a before short-circuit.
		let actionRan = false;
		class FinalSayPolicy extends BasePolicy {
			override before(): HookResponse {
				return true;
			}

			override after(
				_current: UserPayload | null,
				_name: string,
				_result: AuthorizationResponse,
			): HookResponse {
				return AuthorizationResponse.deny("vetoed", 403);
			}

			act(): boolean {
				actionRan = true;
				return true;
			}
		}

		const response = await new Bouncer(owner)
			.with(FinalSayPolicy)
			.execute("act");
		expect(response.authorized).toBe(false);
		expect(response.message).toBe("vetoed");
		expect(actionRan).toBe(false);
	});
});
