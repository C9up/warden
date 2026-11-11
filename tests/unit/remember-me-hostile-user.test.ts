/**
 * The remember-me revival path strips prototype-pollution keys from the user.
 *
 * `AuthManager.verify/authenticate` and the session path strip `__proto__`,
 * `constructor` and `prototype` from every user; the remember-me revival did
 * not, so a `findUser` returning a JSON-decoded row with such a key reached
 * `ctx.auth.user` (and the session) through that path alone.
 */
import { describe, expect, it } from "vitest";
import { Authenticator } from "../../src/Authenticator.js";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import type { WardenContext } from "../../src/middleware.js";
import { MemoryRememberMeTokenDriver } from "../../src/RememberMeToken.js";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";

const HOSTILE =
	'{"id":"u1","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"prototype":1}';

function hostileUser(): UserPayload {
	const parsed: unknown = JSON.parse(HOSTILE);
	if (typeof parsed !== "object" || parsed === null) {
		throw new Error("fixture is not an object");
	}
	const id = Reflect.get(parsed, "id");
	if (typeof id !== "string") throw new Error("fixture has no id");
	// The own `__proto__` key survives JSON.parse and the spread (which
	// defines own properties); that is the hostile shape.
	const user = { ...parsed, id };
	expect(Object.hasOwn(user, "__proto__")).toBe(true);
	return user;
}

function session(): SessionStore {
	const values = new Map<string, unknown>();
	return {
		get: (key) => values.get(key),
		put: (key, value) => {
			values.set(key, value);
		},
		forget: (key) => {
			values.delete(key);
		},
		regenerate: () => {},
	};
}

function app() {
	const strategy = new SessionStrategy({
		findUser: async () => hostileUser(),
		rememberMeTokens: new MemoryRememberMeTokenDriver(),
		rememberMeAge: 3600,
	});
	const manager = new AuthManager({
		default: "web",
		guards: { web: strategy },
	});
	return { strategy, manager };
}

function expectClean(user: UserPayload | undefined): void {
	expect(user?.id).toBe("u1");
	if (user === undefined) return;
	for (const key of ["__proto__", "constructor", "prototype"]) {
		expect(Object.hasOwn(user, key)).toBe(false);
	}
}

describe("warden > remember-me revival sanitises the user", () => {
	it("through the request authenticator (ctx.auth.user)", async () => {
		const { strategy, manager } = app();
		const cookie = await strategy.issueRememberMeToken({ id: "u1" });
		const jar = new Map<string, string>();
		if (cookie !== null) jar.set("remember_web", cookie);
		const store = session();
		const ctx: WardenContext = {
			request: {
				headers: () => ({}),
				encryptedCookie: (name) => jar.get(name) ?? null,
			},
			response: {
				status: () => undefined,
				json: () => undefined,
				encryptedCookie: (name, value) => {
					jar.set(name, value);
				},
				clearCookie: (name) => {
					jar.delete(name);
				},
			},
			session: store,
		};
		const auth = new Authenticator(ctx, manager);

		expect(await auth.check()).toBe(true);
		expectClean(auth.user);
	});

	it("through AuthManager.authenticateViaRememberMeToken", async () => {
		const { strategy, manager } = app();
		const cookie = await strategy.issueRememberMeToken({ id: "u1" });

		const revived = await manager.authenticateViaRememberMeToken(cookie);

		expectClean(revived?.user);
	});
});
