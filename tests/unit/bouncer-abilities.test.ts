import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { WardenError } from "../../src/errors.js";

function user(overrides: Partial<UserPayload> = {}): UserPayload {
	return { id: "u1", ...overrides };
}

describe("warden > bouncer > abilities", () => {
	it("denies a guest WITHOUT invoking a non-allowGuest callback (D5 step 2)", async () => {
		let called = false;
		const ability = Bouncer.ability(() => {
			called = true;
			return true;
		});
		const bouncer = new Bouncer(null);

		expect(await bouncer.allows(ability)).toBe(false);
		expect(called).toBe(false);
	});

	it("runs an allowGuest callback with a null user and can allow it", async () => {
		const ability = Bouncer.ability(
			{ allowGuest: true },
			(current) => current === null,
		);
		expect(await new Bouncer(null).allows(ability)).toBe(true);
	});

	it("allows/denies return booleans, never throw on denial, and denies === !allows", async () => {
		const denyAll = Bouncer.ability(() => false);
		const bouncer = new Bouncer(user());

		await expect(bouncer.allows(denyAll)).resolves.toBe(false);
		await expect(bouncer.denies(denyAll)).resolves.toBe(true);

		const allowAll = Bouncer.ability(() => true);
		expect(await bouncer.denies(allowAll)).toBe(
			!(await bouncer.allows(allowAll)),
		);
	});

	it("execute returns the full response with message + status", async () => {
		const ability = Bouncer.ability(() =>
			AuthorizationResponse.deny("teapot", 418),
		);
		const response = await new Bouncer(user()).execute(ability);

		expect(response.authorized).toBe(false);
		expect(response.message).toBe("teapot");
		expect(response.status).toBe(418);
	});

	it("authorize resolves on allow and throws WARDEN_AUTHORIZATION_FAILURE (status 403) on deny", async () => {
		const bouncer = new Bouncer(user());
		await expect(
			bouncer.authorize(Bouncer.ability(() => true)),
		).resolves.toBeUndefined();

		let thrown: unknown;
		try {
			await bouncer.authorize(Bouncer.ability(() => false));
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(WardenError);
		if (thrown instanceof WardenError) {
			expect(thrown.code).toBe("WARDEN_AUTHORIZATION_FAILURE");
			expect(thrown.status).toBe(403);
		}
	});

	it("propagates the denial message + status onto the thrown error (for 56.6 mapping)", async () => {
		const ability = Bouncer.ability(() =>
			AuthorizationResponse.deny("forbidden", 451),
		);
		let thrown: unknown;
		try {
			await new Bouncer(user()).authorize(ability);
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(WardenError);
		if (thrown instanceof WardenError) {
			expect(thrown.message).toBe("forbidden");
			expect(thrown.status).toBe(451);
		}
	});

	it("resolves abilities by name AND by reference with identical results (AC9)", async () => {
		const ability = Bouncer.ability((current) => current.id === "u1");
		const bouncer = new Bouncer(user(), { isU1: ability });

		expect(await bouncer.allows("isU1")).toBe(await bouncer.allows(ability));
		expect(await bouncer.allows("isU1")).toBe(true);
	});

	it("passes args to the callback by reference", async () => {
		const ability = Bouncer.ability(
			(current, postAuthorId: string) => current.id === postAuthorId,
		);
		const bouncer = new Bouncer(user());

		expect(await bouncer.allows(ability, "u1")).toBe(true);
		expect(await bouncer.allows(ability, "someone-else")).toBe(false);
	});

	it("throws WARDEN_UNKNOWN_ABILITY for an unregistered name", async () => {
		await expect(new Bouncer(user()).execute("ghost")).rejects.toMatchObject({
			code: "WARDEN_UNKNOWN_ABILITY",
		});
	});

	it("the deny() convenience mirrors AuthorizationResponse.deny (default 403)", () => {
		const bouncer = new Bouncer(user());
		expect(bouncer.deny().status).toBe(403);
		expect(bouncer.deny("x", 400).message).toBe("x");
		expect(bouncer.deny("x", 400).status).toBe(400);
	});
});
