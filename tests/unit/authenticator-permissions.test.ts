/**
 * `ctx.auth.hasPermission()` / `hasAllPermissions()`: the per-request
 * Authenticator answers permission questions through the AuthManager, so the
 * RightsResolver decides and the access token narrows. The payload's own
 * `permissions` array is not an input.
 */
import { describe, expect, it } from "vitest";
import {
	AccessTokensProvider,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import { Authenticator } from "../../src/Authenticator.js";
import {
	AuthManager,
	type AuthStrategy,
	type UserPayload,
} from "../../src/AuthManager.js";
import type { WardenContext } from "../../src/middleware.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";

function defined<T>(value: T | null | undefined): T {
	if (value == null) throw new Error("expected a defined value");
	return value;
}

function ctxWith(headers: Record<string, string>): WardenContext {
	return {
		request: { headers: () => headers },
		response: { status: () => undefined, json: () => undefined },
	};
}

/** A JWT-like guard: the token "good" carries whatever payload it is given. */
function payloadGuard(user: UserPayload): AuthStrategy {
	return {
		name: "jwt",
		async authenticate() {
			return { authenticated: false };
		},
		async verify(token) {
			return token === "good"
				? { authenticated: true, user: { ...user } }
				: { authenticated: false };
		},
	};
}

const rights = () =>
	new RightsResolver(
		new MemoryRightsStore()
			.defineRole("editor", ["posts.edit", "posts.read"])
			.assignRole("u1", "editor")
			.grant("u1", "orders.write")
			.grant("u1", "billing.read", { tenant: "acme" }),
	);

async function signedIn(user: UserPayload): Promise<Authenticator> {
	const manager = new AuthManager({
		default: "jwt",
		guards: { jwt: payloadGuard(user) },
		rights: rights(),
	});
	const auth = new Authenticator(
		ctxWith({ authorization: "Bearer good" }),
		manager,
	);
	await auth.authenticate();
	return auth;
}

describe("warden > Authenticator permission checks", () => {
	it("accepts a permission the store grants although the payload carries none", async () => {
		const auth = await signedIn({ id: "u1" });

		expect(auth.permissions).toBeUndefined();
		expect(await auth.hasPermission("posts.edit")).toBe(true);
		expect(await auth.hasPermission("orders.write")).toBe(true);
		expect(
			await auth.hasAllPermissions([
				"posts.edit",
				"posts.read",
				"orders.write",
			]),
		).toBe(true);
	});

	it("refuses a permission only the payload carries", async () => {
		const auth = await signedIn({
			id: "u1",
			permissions: ["admin.everything"],
		});

		expect(auth.permissions).toEqual(["admin.everything"]);
		expect(await auth.hasPermission("admin.everything")).toBe(false);
		expect(
			await auth.hasAllPermissions(["posts.edit", "admin.everything"]),
		).toBe(false);
	});

	it("resolves within the requested scope", async () => {
		const auth = await signedIn({ id: "u1" });

		expect(await auth.hasPermission("billing.read")).toBe(false);
		expect(await auth.hasPermission("billing.read", { tenant: "acme" })).toBe(
			true,
		);
		expect(
			await auth.hasAllPermissions(["billing.read"], { tenant: "other" }),
		).toBe(false);
	});

	it("refuses a permission the user holds when the access token lacks the ability", async () => {
		const tokens = new AccessTokensProvider({
			store: new MemoryAccessTokenStore(),
		});
		const manager = new AuthManager({
			default: "api",
			guards: {
				api: new ApiKeyStrategy({
					tokens,
					findUser: async (id) => (id === "u1" ? { id: "u1" } : null),
				}),
			},
			rights: rights(),
		});
		const value = defined(
			(await tokens.create({ id: "u1" }, ["posts.read"])).value,
		).release();
		const auth = new Authenticator(
			ctxWith({ authorization: `Bearer ${value}` }),
			manager,
		);
		await auth.authenticate();

		expect(await auth.hasPermission("posts.read")).toBe(true);
		expect(await auth.hasPermission("posts.edit")).toBe(false);
		expect(await auth.hasAllPermissions(["posts.read", "posts.edit"])).toBe(
			false,
		);
	});

	it("refuses every permission to a guest", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: payloadGuard({ id: "u1" }) },
			rights: rights(),
		});
		const auth = new Authenticator(ctxWith({}), manager);

		expect(await auth.hasPermission("posts.edit")).toBe(false);
		expect(await auth.hasAllPermissions([])).toBe(false);
	});
});
