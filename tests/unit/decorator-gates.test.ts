/**
 * The decorator gates hold however the route is declared: an authorization
 * decorator without `@Guard` still authenticates (with the default guard),
 * and an action inherited from a parent controller keeps its parent's guard
 * and authorization.
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import {
	AccessTokensProvider,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import { AuthManager, type AuthStrategy } from "../../src/AuthManager.js";
import {
	Guard,
	getGuardMetadata,
	Permission,
	RequireMfa,
	Role,
} from "../../src/Guard.js";
import { type WardenContext, wardenMiddleware } from "../../src/middleware.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import { Secret } from "../../src/Secret.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";
import { SessionStrategy } from "../../src/strategies/SessionStrategy.js";

function defined<T>(value: T | null | undefined): T {
	if (value == null) throw new Error("expected a defined value");
	return value;
}

/** Bearer tokens this guard knows, mapped to the user each one is. */
const users: Record<string, { id: string; roles: string[]; mfa?: boolean }> = {
	admin: { id: "a", roles: ["admin"] },
	"admin-mfa": { id: "a", roles: ["admin"], mfa: true },
	member: { id: "m", roles: ["member"] },
};

const jwt: AuthStrategy = {
	name: "jwt",
	async authenticate() {
		return { authenticated: false };
	},
	async verify(token) {
		const user = users[token];
		return user
			? { authenticated: true, user: { ...user } }
			: { authenticated: false, error: "bad token" };
	},
};

function manager(): AuthManager {
	const store = new MemoryRightsStore();
	store.defineRole("admin", ["users.delete"]);
	return new AuthManager({
		default: "jwt",
		guards: { jwt },
		rights: new RightsResolver(store),
	});
}

async function call(
	controller: object,
	action: string,
	token?: string,
): Promise<{ status: number | undefined; reached: boolean }> {
	const auth = manager();
	let status: number | undefined;
	let reached = false;
	const headers: Record<string, string> = token
		? { authorization: `Bearer ${token}` }
		: {};
	const ctx: WardenContext = {
		request: { headers: () => headers },
		response: {
			status(code) {
				status = code;
			},
			json() {},
		},
		route: { controller, action },
		containerResolver: {
			async make(t) {
				if (t === AuthManager) return auth;
				throw new Error(`No binding for ${String(t)}`);
			},
		},
	};
	await wardenMiddleware(ctx, () => {
		reached = true;
	});
	return { status, reached };
}

describe("warden > an authorization decorator without @Guard still authenticates", () => {
	class Users {
		@Role("admin")
		roleOnly() {}

		@Permission("users.delete")
		permissionOnly() {}

		@RequireMfa()
		mfaOnly() {}

		@Role("admin")
		@Permission("users.delete")
		@RequireMfa()
		destroy() {}

		open() {}
	}
	const users = Users.prototype;

	for (const action of ["roleOnly", "permissionOnly", "mfaOnly", "destroy"]) {
		it(`${action}: refuses an anonymous request with 401`, async () => {
			expect(await call(users, action)).toEqual({
				status: 401,
				reached: false,
			});
		});
	}

	it("refuses a user without the role or permission with 403", async () => {
		for (const action of ["roleOnly", "permissionOnly"]) {
			expect(await call(users, action, "member")).toEqual({
				status: 403,
				reached: false,
			});
		}
	});

	it("refuses a user who did not step up with 403", async () => {
		expect(await call(users, "mfaOnly", "member")).toEqual({
			status: 403,
			reached: false,
		});
	});

	it("lets the right user through", async () => {
		expect(await call(users, "roleOnly", "admin")).toEqual({
			status: undefined,
			reached: true,
		});
		expect(await call(users, "permissionOnly", "admin")).toEqual({
			status: undefined,
			reached: true,
		});
		expect(await call(users, "destroy", "admin-mfa")).toEqual({
			status: undefined,
			reached: true,
		});
	});

	it("leaves an undecorated action public", async () => {
		expect(await call(users, "open")).toEqual({
			status: undefined,
			reached: true,
		});
	});
});

describe("warden > an inherited action keeps its parent's decorators", () => {
	class AdminController {
		@Guard("jwt")
		@Role("admin")
		index() {}
	}
	class UsersController extends AdminController {}
	class AuditController extends UsersController {}
	class OverridingController extends AdminController {
		override index() {}
	}
	class NarrowingController extends AdminController {
		@Guard("jwt")
		@Role("member")
		override index() {}
	}

	it("guards the parent's own route", async () => {
		expect((await call(AdminController.prototype, "index")).status).toBe(401);
	});

	it("guards the subclass route to the same action", async () => {
		expect(await call(UsersController.prototype, "index")).toEqual({
			status: 401,
			reached: false,
		});
		expect(
			(await call(UsersController.prototype, "index", "member")).status,
		).toBe(403);
		expect(
			(await call(UsersController.prototype, "index", "admin")).reached,
		).toBe(true);
	});

	it("guards through several levels of inheritance", async () => {
		expect((await call(AuditController.prototype, "index")).status).toBe(401);
		expect(
			(await call(AuditController.prototype, "index", "member")).status,
		).toBe(403);
	});

	it("keeps the parent's decorators on an override that declares none", async () => {
		expect(getGuardMetadata(OverridingController.prototype, "index")).toEqual([
			"jwt",
		]);
		expect((await call(OverridingController.prototype, "index")).status).toBe(
			401,
		);
		expect(
			(await call(OverridingController.prototype, "index", "member")).status,
		).toBe(403);
	});

	it("lets an override replace a decorator it declares itself", async () => {
		expect(
			(await call(NarrowingController.prototype, "index", "member")).reached,
		).toBe(true);
		expect(
			(await call(NarrowingController.prototype, "index", "admin")).status,
		).toBe(403);
	});
});

describe("warden > @Permission on a token request is an intersection", () => {
	const store = new MemoryRightsStore();
	store.grant("granted", "orders.write");
	const tokens = new AccessTokensProvider({
		store: new MemoryAccessTokenStore(),
	});
	const findUser = async (id: string | number) => ({ id: String(id) });
	const manager = new AuthManager({
		default: "api",
		guards: {
			api: new ApiKeyStrategy({ tokens, findUser }),
			web: new SessionStrategy({ findUser }),
		},
		rights: new RightsResolver(store),
	});

	class Orders {
		@Guard("api", "web")
		@Permission("orders.write")
		create() {}
	}

	async function attempt(opts: {
		token?: string;
		sessionUser?: string;
	}): Promise<{ status: number | undefined; reached: boolean }> {
		let status: number | undefined;
		let reached = false;
		const values = new Map<string, unknown>();
		if (opts.sessionUser !== undefined) {
			values.set("auth_user_id", opts.sessionUser);
		}
		const headers: Record<string, string> =
			opts.token === undefined ? {} : { authorization: `Bearer ${opts.token}` };
		const ctx: WardenContext = {
			request: { headers: () => headers },
			response: {
				status(code) {
					status = code;
				},
				json() {},
			},
			session: {
				get: (key) => values.get(key),
				put: (key, value) => {
					values.set(key, value);
				},
				forget: (key) => {
					values.delete(key);
				},
				regenerate: () => {},
			},
			route: { controller: Orders.prototype, action: "create" },
			containerResolver: {
				async make(t) {
					if (t === AuthManager) return manager;
					throw new Error(`No binding for ${String(t)}`);
				},
			},
		};
		await wardenMiddleware(ctx, () => {
			reached = true;
		});
		return { status, reached };
	}

	async function mint(userId: string, abilities: string[]): Promise<string> {
		const value = (await tokens.create({ id: userId }, abilities)).value;
		if (value === undefined) throw new Error("expected a token value");
		return value.release();
	}

	it("refuses a user without the permission whose token has a same-named ability", async () => {
		expect(
			await attempt({ token: await mint("plain", ["orders.write"]) }),
		).toEqual({ status: 403, reached: false });
	});

	it("refuses a user with the permission whose token does not allow it", async () => {
		expect(
			await attempt({ token: await mint("granted", ["orders.read"]) }),
		).toEqual({ status: 403, reached: false });
	});

	it("admits a user with the permission whose token allows it", async () => {
		expect(
			await attempt({ token: await mint("granted", ["orders.write"]) }),
		).toEqual({ status: undefined, reached: true });
		expect(await attempt({ token: await mint("granted", ["*"]) })).toEqual({
			status: undefined,
			reached: true,
		});
	});

	it("leaves a session user to their own permissions", async () => {
		expect(await attempt({ sessionUser: "granted" })).toEqual({
			status: undefined,
			reached: true,
		});
		expect(await attempt({ sessionUser: "plain" })).toEqual({
			status: 403,
			reached: false,
		});
	});

	it("applies the same rule to hasPermission / hasAllPermissions", async () => {
		const restricted = defined(
			await tokens.verify(new Secret(await mint("granted", ["orders.read"]))),
		);
		const viaToken = { id: "granted", currentAccessToken: restricted };

		expect(await manager.hasPermission(viaToken, "orders.write")).toBe(false);
		expect(await manager.hasAllPermissions(viaToken, ["orders.write"])).toBe(
			false,
		);
		expect(await manager.hasPermission({ id: "granted" }, "orders.write")).toBe(
			true,
		);
	});
});
