/**
 * The per-request authenticator's upstream surface (`@adonisjs/auth`
 * `Authenticator` and its guards): `authenticate()`/`authenticateUsing()`
 * resolve to the user, `use()` without a name is the default guard,
 * `defaultGuard`, and every guard carries `getUserOrFail`, `check`,
 * `authenticationAttempted`, `authenticateAsClient`, plus `createToken` /
 * `invalidateToken` on an access-tokens guard.
 *
 * Each idiom below threw a TypeError (or resolved to `undefined`) before.
 */
import { describe, expect, it } from "vitest";
import {
	AccessTokensProvider,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import { Authenticator } from "../../src/Authenticator.js";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import {
	E_UNAUTHORIZED_ACCESS,
	E_WARDEN_STRATEGY_CANNOT_ISSUE,
} from "../../src/errors.js";
import type { WardenContext } from "../../src/middleware.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";

function memorySession(seed: Record<string, unknown> = {}): SessionStore {
	const store = new Map<string, unknown>(Object.entries(seed));
	return {
		get: (key) => store.get(key),
		put: (key, value) => {
			store.set(key, value);
		},
		forget: (key) => {
			store.delete(key);
		},
		regenerate: () => {},
	};
}

function setup() {
	const tokens = new AccessTokensProvider({
		store: new MemoryAccessTokenStore(),
	});
	const web = new SessionStrategy({
		findUser: async (id) => ({ id: String(id), email: "a@b.c" }),
	});
	const api = new ApiKeyStrategy({
		tokens,
		findUser: async (id) => ({ id: String(id) }),
	});
	const manager = new AuthManager({ default: "web", guards: { web, api } });
	return { manager, tokens, web };
}

function contextFor(
	options: { headers?: Record<string, string>; session?: SessionStore } = {},
): WardenContext {
	return {
		request: { headers: () => options.headers ?? {} },
		response: { status() {}, json() {} },
		session: options.session,
	};
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
	try {
		await promise;
	} catch (error) {
		return error;
	}
	throw new Error("expected a rejection");
}

describe("warden > Authenticator upstream surface", () => {
	it("authenticate() resolves to the user", async () => {
		const { manager, web } = setup();
		const session = memorySession(
			web.authenticateAsClient({ id: "u1" }).session,
		);
		const auth = new Authenticator(contextFor({ session }), manager);

		const user = await auth.authenticate();

		expect(user.id).toBe("u1");
		expect(user).toBe(auth.user);
	});

	it("authenticateUsing() resolves to the user", async () => {
		const { manager, web } = setup();
		const session = memorySession(
			web.authenticateAsClient({ id: "u1" }).session,
		);
		const auth = new Authenticator(contextFor({ session }), manager);

		const user = await auth.authenticateUsing(["api", "web"]);

		expect(user.id).toBe("u1");
	});

	it("defaultGuard names the default guard", () => {
		const { manager } = setup();
		expect(new Authenticator(contextFor(), manager).defaultGuard).toBe("web");
	});

	it("use() without a name is the default guard's accessor", async () => {
		const { manager, web } = setup();
		const session = memorySession(
			web.authenticateAsClient({ id: "u1" }).session,
		);
		const auth = new Authenticator(contextFor({ session }), manager);
		await auth.authenticate();

		expect(auth.use()).toBe(auth.use("web"));
		expect(auth.use().user?.id).toBe("u1");
	});

	it("a guard's authenticate() resolves to the user", async () => {
		const { manager, web } = setup();
		const session = memorySession(
			web.authenticateAsClient({ id: "u1" }).session,
		);
		const auth = new Authenticator(contextFor({ session }), manager);

		expect((await auth.use("web").authenticate()).id).toBe("u1");
	});

	it("getUserOrFail() on a guard throws E_UNAUTHORIZED_ACCESS for a guest", async () => {
		const { manager } = setup();
		const auth = new Authenticator(contextFor(), manager);

		const error = await rejection(
			Promise.resolve().then(() => auth.use("api").getUserOrFail()),
		);
		expect(error).toBeInstanceOf(E_UNAUTHORIZED_ACCESS);
	});

	it("check() and authenticationAttempted on a guard", async () => {
		const { manager, web } = setup();
		const session = memorySession(
			web.authenticateAsClient({ id: "u1" }).session,
		);
		const auth = new Authenticator(contextFor({ session }), manager);

		expect(auth.use("web").authenticationAttempted).toBe(false);
		expect(await auth.use("api").check()).toBe(false);
		expect(auth.use("api").authenticationAttempted).toBe(true);
		expect(await auth.use("web").check()).toBe(true);
		expect(auth.use("web").authenticationAttempted).toBe(true);
		expect(auth.use("web").getUserOrFail().id).toBe("u1");
	});

	it("authenticationAttempted stays false for a guard after the one that answered", async () => {
		const { manager, web } = setup();
		const session = memorySession(
			web.authenticateAsClient({ id: "u1" }).session,
		);
		const auth = new Authenticator(contextFor({ session }), manager);

		await auth.authenticateUsing(["web", "api"]);

		expect(auth.use("web").authenticationAttempted).toBe(true);
		expect(auth.use("api").authenticationAttempted).toBe(false);
	});

	it("authenticateAsClient() on a guard delegates to its strategy", async () => {
		const { manager } = setup();
		const auth = new Authenticator(contextFor(), manager);

		const client = await auth.use("web").authenticateAsClient({ id: "u1" });
		expect(client.session?.auth_user_id).toBe("u1");
		const tokenClient = await auth
			.use("api")
			.authenticateAsClient({ id: "u1" }, ["*"]);
		expect(tokenClient.headers?.authorization).toMatch(/^Bearer /);
	});

	it("createToken() mints through the access-tokens guard", async () => {
		const { manager } = setup();
		const auth = new Authenticator(contextFor(), manager);

		const token = await auth
			.use("api")
			.createToken({ id: "u1" }, ["orders:read"]);
		const value = token.value?.release() ?? "";
		const verified = await manager.verify(value, "api");

		expect(verified.user?.id).toBe("u1");
		expect(verified.user?.currentAccessToken?.allows("orders:read")).toBe(true);
	});

	it("invalidateToken() revokes the token this request came in with", async () => {
		const { manager, tokens } = setup();
		const value =
			(await tokens.create({ id: "u1" }, ["*"])).value?.release() ?? "";
		const other =
			(await tokens.create({ id: "u1" }, ["*"])).value?.release() ?? "";
		const auth = new Authenticator(
			contextFor({ headers: { authorization: `Bearer ${value}` } }),
			manager,
		);
		await auth.authenticateUsing(["api"]);

		expect(await auth.use("api").invalidateToken()).toBe(true);

		expect((await manager.verify(value, "api")).authenticated).toBe(false);
		// Only that one: the user's other tokens keep working.
		expect((await manager.verify(other, "api")).authenticated).toBe(true);
	});

	it("invalidateToken() without a token on the request is an unauthorized access", async () => {
		const { manager } = setup();
		const auth = new Authenticator(contextFor(), manager);

		expect(await rejection(auth.use("api").invalidateToken())).toBeInstanceOf(
			E_UNAUTHORIZED_ACCESS,
		);
	});

	it("createToken() on a guard that issues no access tokens says so", async () => {
		const { manager } = setup();
		const auth = new Authenticator(contextFor(), manager);
		const user: UserPayload = { id: "u1" };

		const error = await rejection(auth.use("web").createToken(user));
		expect(error).toBeInstanceOf(E_WARDEN_STRATEGY_CANNOT_ISSUE);
		expect(error).toMatchObject({ code: "E_WARDEN_STRATEGY_CANNOT_ISSUE" });
	});
});
