/**
 * The access-tokens guard: verification through a token provider, the user
 * reloaded on every request, and the token's abilities kept on
 * `currentAccessToken` — never merged into the user's permissions.
 */
import { describe, expect, it } from "vitest";
import {
	AccessToken,
	AccessTokensProvider,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import { Authenticator } from "../../src/Authenticator.js";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import { apiKeyGuard } from "../../src/config.js";
import type { WardenContext } from "../../src/middleware.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";

function defined<T>(value: T | null | undefined): T {
	if (value == null) throw new Error("expected a defined value");
	return value;
}

function setup(users: Record<string, UserPayload>) {
	const store = new MemoryAccessTokenStore();
	const tokens = new AccessTokensProvider({ store });
	const strategy = new ApiKeyStrategy({
		tokens,
		findUser: async (id) => users[String(id)] ?? null,
	});
	return { store, tokens, strategy };
}

async function mint(
	tokens: AccessTokensProvider,
	user: { id: string },
	abilities?: string[],
): Promise<string> {
	return defined((await tokens.create(user, abilities)).value).release();
}

function ctxWith(
	manager: AuthManager,
	headers: Record<string, string>,
): WardenContext {
	return {
		request: { headers: () => headers },
		response: { status: () => undefined, json: () => undefined },
		containerResolver: {
			make: async (token) => {
				if (token === AuthManager) return manager;
				throw new Error(`no binding for ${String(token)}`);
			},
		},
	};
}

describe("warden > ApiKeyStrategy — configuration", () => {
	it("defaults the header to x-api-key and honours a custom one", () => {
		const { tokens } = setup({});
		const findUser = async () => null;
		expect(new ApiKeyStrategy({ tokens, findUser }).headerName).toBe(
			"x-api-key",
		);
		expect(
			new ApiKeyStrategy({ tokens, findUser, headerName: "x-token" })
				.headerName,
		).toBe("x-token");
	});

	it("refuses a config with no token provider (the earlier findByKey shape)", () => {
		const legacy: unknown = { findByKey: async () => null };
		const build = () =>
			Reflect.construct(ApiKeyStrategy, [legacy]) instanceof ApiKeyStrategy;
		expect(build).toThrow(/needs `tokens`/);
	});

	it("rejects credential-based auth (must use verify with the token)", async () => {
		const { strategy } = setup({});
		await expect(
			strategy.authenticate({ email: "a", password: "b" }),
		).rejects.toThrow(/does not support credential-based auth/);
	});
});

describe("warden > ApiKeyStrategy — verify", () => {
	it("authenticates a minted token and hands the token to the user", async () => {
		const { tokens, strategy } = setup({ u1: { id: "u1" } });
		const value = await mint(tokens, { id: "u1" }, ["orders:read"]);

		const out = await strategy.verify(value);

		expect(out.authenticated).toBe(true);
		expect(out.user?.id).toBe("u1");
		const current = defined(out.user?.currentAccessToken);
		expect(current).toBeInstanceOf(AccessToken);
		expect(current.allows("orders:read")).toBe(true);
		expect(current.denies("orders:write")).toBe(true);
	});

	it("refuses an unknown, malformed or tampered token", async () => {
		const { tokens, strategy } = setup({ u1: { id: "u1" } });
		const value = await mint(tokens, { id: "u1" });

		for (const presented of [
			"nope",
			"oat_",
			value.slice(4),
			`${value.slice(0, -1)}${value.endsWith("A") ? "B" : "A"}`,
		]) {
			expect(await strategy.verify(presented)).toEqual({
				authenticated: false,
				error: "Invalid access token",
			});
		}
	});

	it("refuses a valid token whose account is gone", async () => {
		const { tokens, strategy } = setup({});
		const value = await mint(tokens, { id: "deleted" });

		const out = await strategy.verify(value);

		expect(out.authenticated).toBe(false);
	});

	it("does not touch the object the application returned", async () => {
		const source: UserPayload = { id: "u1", permissions: ["read"] };
		const { tokens, strategy } = setup({ u1: source });
		await strategy.verify(await mint(tokens, { id: "u1" }));

		expect(source).toEqual({ id: "u1", permissions: ["read"] });
	});
});

describe("warden > token abilities never become user permissions", () => {
	it("keeps the user's own permissions, whatever the token carries", async () => {
		const { tokens, strategy } = setup({ u1: { id: "u1", permissions: [] } });
		const value = await mint(tokens, { id: "u1" }, ["orders:write"]);

		const out = await strategy.verify(value);

		// A token ability sharing a permission's name granted that permission
		// to a user who does not hold it.
		expect(out.user?.permissions).toEqual([]);
		expect(out.user?.currentAccessToken?.allows("orders:write")).toBe(true);
	});

	it("leaves ctx.auth.permissions and the rights resolver to the user alone", async () => {
		const { tokens, strategy } = setup({
			u1: { id: "u1", permissions: ["profile:read"] },
		});
		const manager = new AuthManager({
			default: "api",
			guards: { api: strategy },
		});
		const value = await mint(tokens, { id: "u1" }, ["orders:write"]);
		const auth = new Authenticator(
			ctxWith(manager, { authorization: `Bearer ${value}` }),
			manager,
		);

		await auth.authenticate();

		expect(auth.permissions).toEqual(["profile:read"]);
		expect(
			await manager.hasPermission(defined(auth.user), "orders:write"),
		).toBe(false);
		expect(auth.user?.currentAccessToken?.allows("orders:write")).toBe(true);
	});

	it("reads the token from the configured header too", async () => {
		const { tokens } = setup({});
		const manager = new AuthManager({
			default: "access_tokens",
			guards: {
				access_tokens: apiKeyGuard({
					tokens,
					findUser: async (id) => ({ id: String(id) }),
				}),
			},
		});
		const value = await mint(tokens, { id: "u7" });
		const auth = new Authenticator(
			ctxWith(manager, { "x-api-key": value }),
			manager,
		);

		await auth.authenticate();

		expect(auth.user?.id).toBe("u7");
	});
});

describe("warden > ApiKeyStrategy — minting and revoking", () => {
	it("authenticateAsClient mints a real token the guard accepts", async () => {
		const { strategy } = setup({ u1: { id: "u1" } });
		const manager = new AuthManager({
			default: "api",
			guards: { api: strategy },
		});

		const client = await strategy.authenticateAsClient({ id: "u1" }, ["a"]);
		const auth = new Authenticator(
			ctxWith(manager, client.headers ?? {}),
			manager,
		);
		await auth.authenticate();

		expect(auth.user?.currentAccessToken?.abilities).toEqual(["a"]);
	});

	it("invalidateToken revokes the token it is handed", async () => {
		const { tokens, strategy } = setup({ u1: { id: "u1" } });
		const value = await mint(tokens, { id: "u1" });

		expect(await strategy.invalidateToken(value)).toBe(true);
		expect((await strategy.verify(value)).authenticated).toBe(false);
		expect(await strategy.invalidateToken(value)).toBe(false);
	});

	it("createToken goes through the provider", async () => {
		const { store, strategy } = setup({});
		const token = await strategy.createToken({ id: "u1" }, ["x"], {
			name: "CLI",
		});

		const row = defined(await store.find(token.identifier));
		expect(row.name).toBe("CLI");
		expect(row.abilities).toEqual(["x"]);
	});
});
