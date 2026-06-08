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

	it("AuthorizationResponse.deny defaults to 403; allow() carries no status", () => {
		expect(AuthorizationResponse.deny().status).toBe(403);
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
});
