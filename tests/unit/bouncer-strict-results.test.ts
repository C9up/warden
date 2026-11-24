/**
 * What counts as an authorization: only `true` or an allowing
 * `AuthorizationResponse`. A check written in loosely typed code — a column
 * that holds `"false"`, a lookup result, a number — must deny, never grant; a
 * `before` / `after` hook that answers such a value has no opinion.
 */
import { afterEach, describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import type { HookResponse } from "../../src/bouncer/types.js";
import { E_AUTHORIZATION_FAILURE } from "../../src/errors.js";

/** A type predicate that checks nothing: what untyped code hands the bouncer. */
function untyped(_value: unknown): _value is boolean {
	return true;
}
const loose = (value: unknown): boolean => (untyped(value) ? value : false);
function untypedResponse(_value: unknown): _value is AuthorizationResponse {
	return true;
}

const LOOSE_VALUES: unknown[] = [
	"no",
	"false",
	"0",
	1,
	{},
	[],
	null,
	undefined,
];
const user: UserPayload = { id: "u1" };
const builder = Bouncer.responseBuilder;

afterEach(() => {
	Bouncer.responseBuilder = builder;
});

describe("warden > bouncer > only a boolean or a response authorizes", () => {
	it.each(LOOSE_VALUES)(
		"an ability returning %j is a denial",
		async (value) => {
			const ability = Bouncer.ability(() => loose(value));
			const bouncer = new Bouncer(user);
			expect(await bouncer.allows(ability)).toBe(false);
			expect(await bouncer.denies(ability)).toBe(true);
			await expect(bouncer.authorize(ability)).rejects.toBeInstanceOf(
				E_AUTHORIZATION_FAILURE,
			);
		},
	);

	it.each(LOOSE_VALUES)(
		"a policy action returning %j is a denial",
		async (value) => {
			class PostPolicy extends BasePolicy {
				edit() {
					return loose(value);
				}
			}
			const bouncer = new Bouncer(user);
			expect(await bouncer.with(PostPolicy).allows("edit")).toBe(false);
			await expect(
				bouncer.with(PostPolicy).authorize("edit"),
			).rejects.toBeInstanceOf(E_AUTHORIZATION_FAILURE);
		},
	);

	it("a before hook answering neither a boolean nor a response lets the action decide", async () => {
		const ran: string[] = [];
		class PostPolicy extends BasePolicy {
			// "Admins may do everything": the column holds the string "false".
			override before(): HookResponse {
				return loose("false");
			}
			destroy() {
				ran.push("destroy");
				return false;
			}
			view() {
				ran.push("view");
				return true;
			}
		}
		const bouncer = new Bouncer(user);
		expect(await bouncer.with(PostPolicy).allows("destroy")).toBe(false);
		expect(await bouncer.with(PostPolicy).allows("view")).toBe(true);
		expect(ran).toEqual(["destroy", "view"]);
	});

	it("an after hook answering neither keeps the response; a boolean still overrides", async () => {
		class PostPolicy extends BasePolicy {
			override after(_user: UserPayload | null, action: string): HookResponse {
				if (action === "override") return true;
				return loose(1);
			}
			destroy() {
				return false;
			}
			view() {
				return true;
			}
			override() {
				return false;
			}
		}
		const bouncer = new Bouncer(user);
		expect(await bouncer.with(PostPolicy).allows("destroy")).toBe(false);
		expect(await bouncer.with(PostPolicy).allows("view")).toBe(true);
		expect(await bouncer.with(PostPolicy).allows("override")).toBe(true);
	});

	it("true and an allowing response still authorize", async () => {
		const bouncer = new Bouncer(user);
		expect(await bouncer.allows(Bouncer.ability(() => true))).toBe(true);
		expect(
			await bouncer.allows(
				Bouncer.ability(() => AuthorizationResponse.allow()),
			),
		).toBe(true);
		expect(await bouncer.allows(Bouncer.ability(async () => true))).toBe(true);
	});

	it("a custom response builder receives a loose value as false", async () => {
		const seen: unknown[] = [];
		Bouncer.responseBuilder = (value) => {
			seen.push(value);
			return value instanceof AuthorizationResponse
				? value
				: value === true
					? AuthorizationResponse.allow()
					: AuthorizationResponse.deny("Nope", 404);
		};
		const bouncer = new Bouncer(user);
		const error = await bouncer
			.authorize(Bouncer.ability(() => loose("yes")))
			.catch((e: unknown) => e);
		expect(seen).toEqual([false]);
		expect(error).toBeInstanceOf(E_AUTHORIZATION_FAILURE);
		if (!(error instanceof E_AUTHORIZATION_FAILURE)) return;
		expect(error.status).toBe(404);
	});

	it("a builder that answers something other than a response is a denial", async () => {
		// What a JavaScript builder can answer: an object that only looks like
		// a response.
		const lookalike: unknown = { authorized: true };
		Bouncer.responseBuilder = () =>
			untypedResponse(lookalike) ? lookalike : AuthorizationResponse.allow();
		expect(await new Bouncer(user).allows(Bouncer.ability(() => true))).toBe(
			false,
		);
	});
});
