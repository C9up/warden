/**
 * A denied `authorize()` throws `E_AUTHORIZATION_FAILURE` — the upstream
 * identifier, verbatim — carrying the `AuthorizationResponse` it was thrown
 * for, so a handler can read the denial's status, message and translation.
 */
import { describe, expect, it } from "vitest";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import { E_AUTHORIZATION_FAILURE, WardenError } from "../../src/errors.js";
import * as barrel from "../../src/index.js";

async function denial(promise: Promise<void>): Promise<unknown> {
	try {
		await promise;
	} catch (error) {
		return error;
	}
	throw new Error("authorize() resolved on a denial");
}

class PostPolicy extends BasePolicy {
	edit() {
		return AuthorizationResponse.deny("Not yours", 404).t(
			"errors.post_not_owned",
			{
				id: 7,
			},
		);
	}
	view() {
		return false;
	}
}

describe("warden > E_AUTHORIZATION_FAILURE", () => {
	it("is what a denied ability throws, with its response", async () => {
		const response = AuthorizationResponse.deny("Nope", 404).t(
			"errors.post_not_found",
			{ id: 7 },
		);
		const bouncer = new Bouncer(
			{ id: "u1" },
			{
				edit: Bouncer.ability(() => response),
			},
		);

		const error = await denial(bouncer.authorize("edit"));

		expect(error).toBeInstanceOf(E_AUTHORIZATION_FAILURE);
		expect(error).toBeInstanceOf(WardenError);
		if (!(error instanceof E_AUTHORIZATION_FAILURE)) return;
		expect(error.code).toBe("E_AUTHORIZATION_FAILURE");
		expect(error.identifier).toBe("errors.E_AUTHORIZATION_FAILURE");
		expect(error.status).toBe(404);
		expect(error.message).toBe("Nope");
		expect(error.response).toBe(response);
		expect(error.response.translation).toEqual({
			identifier: "errors.post_not_found",
			data: { id: 7 },
		});
	});

	it("defaults to 403 and 'Access denied' for a bare false", async () => {
		const bouncer = new Bouncer({ id: "u1" }, undefined, { PostPolicy });

		const error = await denial(bouncer.with("PostPolicy").authorize("view"));

		expect(error).toBeInstanceOf(E_AUTHORIZATION_FAILURE);
		if (!(error instanceof E_AUTHORIZATION_FAILURE)) return;
		expect(error.status).toBe(403);
		expect(error.message).toBe("Access denied");
		expect(error.response.authorized).toBe(false);
	});

	it("a policy denial carries its response too", async () => {
		const bouncer = new Bouncer({ id: "u1" }, undefined, { PostPolicy });

		const error = await denial(bouncer.with("PostPolicy").authorize("edit"));

		expect(error).toBeInstanceOf(E_AUTHORIZATION_FAILURE);
		if (!(error instanceof E_AUTHORIZATION_FAILURE)) return;
		expect(error.status).toBe(404);
		expect(error.response.translation?.identifier).toBe(
			"errors.post_not_owned",
		);
	});

	it("getResponseMessage translates through ctx.i18n, falling back to the message", () => {
		const error = new E_AUTHORIZATION_FAILURE(
			AuthorizationResponse.deny("Not yours").t("errors.post_not_owned", {
				id: 7,
			}),
		);
		const calls: unknown[][] = [];
		const ctx = {
			i18n: {
				t(
					identifier: string,
					data?: Record<string, unknown>,
					options?: unknown,
				) {
					calls.push([identifier, data, options]);
					return `translated:${identifier}`;
				},
			},
		};

		expect(error.getResponseMessage(ctx)).toBe(
			"translated:errors.post_not_owned",
		);
		expect(calls).toEqual([
			["errors.post_not_owned", { id: 7 }, { defaultValue: "Not yours" }],
		]);
		// No i18n on the context: the denial's own message.
		expect(error.getResponseMessage({})).toBe("Not yours");
		// No translation set: the static identifier is looked up.
		const bare = new E_AUTHORIZATION_FAILURE(AuthorizationResponse.deny());
		expect(bare.getResponseMessage(ctx)).toBe(
			"translated:errors.E_AUTHORIZATION_FAILURE",
		);
	});

	it("is exported from the barrel", () => {
		expect(barrel.E_AUTHORIZATION_FAILURE).toBe(E_AUTHORIZATION_FAILURE);
	});
});
