/**
 * A gate decorator that names nothing is refused when it is applied, and an
 * action whose metadata names nothing fails closed in the middleware: an
 * empty requirement read as "no requirement" left the action public.
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { AuthManager, type AuthStrategy } from "../../src/AuthManager.js";
import { E_WARDEN_EMPTY_GATE_REQUIREMENT } from "../../src/errors.js";
import {
	Guard,
	getGuardMetadata,
	getPermissionMetadata,
	getRoleMetadata,
	Permission,
	Role,
} from "../../src/Guard.js";
import { type WardenContext, wardenMiddleware } from "../../src/middleware.js";

class Reports {
	index() {}
	show() {}
}

function apply(decorator: MethodDecorator, action: "index" | "show"): void {
	const descriptor = Object.getOwnPropertyDescriptor(Reports.prototype, action);
	if (descriptor === undefined) throw new Error("no such action");
	decorator(Reports.prototype, action, descriptor);
}

function refusal(run: () => unknown): unknown {
	try {
		run();
	} catch (error) {
		return error;
	}
	throw new Error("expected a refusal");
}

describe("warden > a gate decorator that names nothing is refused at declaration", () => {
	const empty: Array<[string, () => MethodDecorator]> = [
		["@Role()", () => Role()],
		["@Permission()", () => Permission()],
		["@Role(...[])", () => Role(...[])],
		["@Role('')", () => Role("")],
		["@Permission('', '')", () => Permission("", "")],
		// The call a JavaScript caller can write, which the types forbid.
		["@Guard()", () => Reflect.apply(Guard, undefined, [])],
		["@Guard('')", () => Guard("")],
	];

	it.each(empty)("%s throws E_WARDEN_EMPTY_GATE_REQUIREMENT", (name, make) => {
		const error = refusal(() => apply(make(), "index"));
		expect(error).toBeInstanceOf(E_WARDEN_EMPTY_GATE_REQUIREMENT);
		if (!(error instanceof E_WARDEN_EMPTY_GATE_REQUIREMENT)) return;
		expect(error.code).toBe("E_WARDEN_EMPTY_GATE_REQUIREMENT");
		expect(error.message).toContain("Reports.index");
		expect(error.message).toContain(name.slice(0, name.indexOf("(")));
	});

	it("an action with a real name is declared as before", () => {
		class Admin {
			@Guard("jwt", "api")
			@Role("admin")
			@Permission("reports.read")
			index() {}
		}
		expect(getGuardMetadata(Admin.prototype, "index")).toEqual(["jwt", "api"]);
		expect(getRoleMetadata(Admin.prototype, "index")).toEqual(["admin"]);
		expect(getPermissionMetadata(Admin.prototype, "index")).toEqual([
			"reports.read",
		]);
		expect(getRoleMetadata(Admin.prototype, "absent")).toEqual([]);
	});

	it("a refused decorator writes no metadata", () => {
		refusal(() => apply(Role(), "show"));
		expect(
			Reflect.getMetadata(Symbol.for("warden:role"), Reports.prototype, "show"),
		).toBe(undefined);
	});
});

describe("warden > the middleware fails closed on metadata that names nothing", () => {
	const jwt: AuthStrategy = {
		name: "jwt",
		async authenticate() {
			return { authenticated: false };
		},
		async verify() {
			return { authenticated: true, user: { id: "u1", roles: [] } };
		},
	};

	async function call(controller: object, action: string) {
		const auth = new AuthManager({ default: "jwt", guards: { jwt } });
		let reached = false;
		const ctx: WardenContext = {
			request: { headers: () => ({ authorization: "Bearer t" }) },
			response: { status() {}, json() {} },
			route: { controller, action },
			containerResolver: {
				async make(t) {
					if (t === AuthManager) return auth;
					throw new Error(`No binding for ${String(t)}`);
				},
			},
		};
		const outcome = await wardenMiddleware(ctx, () => {
			reached = true;
		}).then(
			() => null,
			(error: unknown) => error,
		);
		return { outcome, reached };
	}

	for (const [key, value] of [
		["warden:role", []],
		["warden:permission", []],
		["warden:guard", []],
		["warden:role", "admin"],
		["warden:permission", [42]],
		["warden:role", [""]],
	] as const) {
		it(`${key} = ${JSON.stringify(value)} written by hand: refused, never public`, async () => {
			class Handmade {
				index() {}
			}
			Reflect.defineMetadata(
				Symbol.for(key),
				value,
				Handmade.prototype,
				"index",
			);
			const { outcome, reached } = await call(Handmade.prototype, "index");
			expect(reached).toBe(false);
			expect(outcome).toBeInstanceOf(E_WARDEN_EMPTY_GATE_REQUIREMENT);
		});
	}

	it("an action without any gate metadata stays public", async () => {
		class Open {
			index() {}
		}
		expect(await call(Open.prototype, "index")).toEqual({
			outcome: null,
			reached: true,
		});
	});
});
