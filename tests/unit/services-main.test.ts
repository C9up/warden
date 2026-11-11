/**
 * The `services/main` singleton before and after the provider binds it: a
 * loader or a promise inspecting the value is not a use of it, and a real use
 * before boot fails with a coded warden error.
 */
import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { AuthManager, type AuthStrategy } from "../../src/AuthManager.js";
import { WardenError } from "../../src/errors.js";
import auth, { clearAuth, setAuth } from "../../src/services/main.js";

const guard: AuthStrategy = {
	name: "jwt",
	async authenticate() {
		return { authenticated: false };
	},
	async verify(token) {
		return token === "good"
			? { authenticated: true, user: { id: "u1" } }
			: { authenticated: false };
	},
};

afterEach(() => {
	clearAuth();
});

describe("warden > services/main", () => {
	it("can be awaited, returned from an async function and inspected before boot", async () => {
		await expect(Promise.resolve(auth)).resolves.toBe(auth);
		const factory = async () => auth;
		await expect(factory()).resolves.toBe(auth);
		expect(Reflect.get(auth, "then")).toBeUndefined();
		expect(Reflect.get(auth, Symbol.toStringTag)).toBeUndefined();
		expect(Reflect.get(auth, Symbol.toPrimitive)).toBeUndefined();
		expect(() => inspect(auth)).not.toThrow();
	});

	it("throws E_WARDEN_NOT_BOOTED on a real member access before boot", () => {
		let caught: unknown;
		try {
			Reflect.get(auth, "verify");
		} catch (error) {
			caught = error;
		}
		expect(caught).toBeInstanceOf(WardenError);
		expect(caught).toMatchObject({ code: "E_WARDEN_NOT_BOOTED" });
		expect(() => auth.verify).toThrow(/WardenProvider\.boot\(\)/);
	});

	it("forwards to the bound manager once the provider set it", async () => {
		setAuth(new AuthManager({ default: "jwt", guards: { jwt: guard } }));

		const { verify } = auth;
		expect((await verify("good")).user?.id).toBe("u1");
		expect(auth.defaultStrategyName).toBe("jwt");
		await expect(Promise.resolve(auth)).resolves.toBe(auth);
	});
});
