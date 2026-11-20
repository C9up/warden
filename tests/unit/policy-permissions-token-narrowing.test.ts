/**
 * A policy's `this.permissions` answers what `ctx.auth.hasPermission()` answers.
 *
 * The coarse checks intersect the user's rights with the abilities of the token
 * the request came in with; the policy path read the user's full set instead.
 * A personal access token minted for `orders:read` could therefore delete
 * orders through any policy written as `this.permissions.has('orders:delete')`.
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import {
	AccessTokensProvider,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import { Authenticator } from "../../src/Authenticator.js";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import { BasePolicy } from "../../src/bouncer/BasePolicy.js";
import { Bouncer } from "../../src/bouncer/Bouncer.js";
import {
	type BouncerRegistry,
	initializeBouncer,
	type WardenContext,
} from "../../src/middleware.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";

class OrderPolicy extends BasePolicy {
	delete() {
		return this.permissions.has("orders:delete");
	}
	read() {
		return this.permissions.has("orders:read");
	}
	deleteAll() {
		return this.permissions.hasAll(["orders:read", "orders:delete"]);
	}
	deleteAny() {
		return this.permissions.hasAny(["orders:delete", "orders:purge"]);
	}
	listed() {
		return [...this.permissions.permissions].join(",") === "orders:read";
	}
	admin() {
		return this.permissions.roles.has("admin");
	}
}

async function setup(abilities: string[]) {
	const store = new MemoryRightsStore()
		.grant("u1", "orders:read")
		.grant("u1", "orders:delete")
		.assignRole("u1", "admin");
	const rights = new RightsResolver(store);
	const tokens = new AccessTokensProvider({
		store: new MemoryAccessTokenStore(),
	});
	const auth = new AuthManager({
		default: "api",
		guards: {
			api: new ApiKeyStrategy({
				tokens,
				findUser: async (id) => ({ id: String(id) }),
			}),
		},
		rights,
	});
	const value = (await tokens.create({ id: "u1" }, abilities)).value?.release();
	const verified = await auth.verify(value ?? "", "api");
	const user = verified.user;
	if (user === undefined) throw new Error("the token did not authenticate");
	return { auth, rights, user };
}

async function bouncerFor(
	auth: AuthManager,
	rights: RightsResolver,
	user: UserPayload,
) {
	const registry: BouncerRegistry = {
		abilities: {},
		policies: { OrderPolicy },
	};
	const bindings = new Map<unknown, unknown>([
		[RightsResolver, rights],
		["bouncer:registry", registry],
	]);
	const ctx: WardenContext = {
		request: { headers: () => ({}) },
		response: { status() {}, json() {} },
		containerResolver: {
			async make(token) {
				if (bindings.has(token)) return bindings.get(token);
				if (token === OrderPolicy) return new OrderPolicy();
				throw new Error(`No binding for ${String(token)}`);
			},
		},
	};
	const authenticator = new Authenticator(ctx, auth);
	authenticator.adopt({ authenticated: true, user }, "api");
	ctx.auth = authenticator;
	await initializeBouncer(ctx, () => {});
	const bouncer = ctx.bouncer;
	if (!(bouncer instanceof Bouncer)) throw new Error("no bouncer attached");
	return bouncer;
}

describe("warden > policy permissions are narrowed by the access token", () => {
	it("refuses a permission the user holds but the token does not allow", async () => {
		const { auth, rights, user } = await setup(["orders:read"]);
		const bouncer = await bouncerFor(auth, rights, user);

		// The coarse answer …
		expect(user.currentAccessToken?.allows("orders:delete")).toBe(false);
		expect(await auth.hasPermission(user, "orders:delete")).toBe(false);
		// … and the policy answer agree.
		expect(await bouncer.with("OrderPolicy").allows("delete")).toBe(false);
		expect(await bouncer.with("OrderPolicy").allows("read")).toBe(true);
	});

	it("narrows hasAll, hasAny and the listed set the same way", async () => {
		const { auth, rights, user } = await setup(["orders:read"]);
		const bouncer = await bouncerFor(auth, rights, user);

		expect(await bouncer.with("OrderPolicy").allows("deleteAll")).toBe(false);
		expect(await bouncer.with("OrderPolicy").allows("deleteAny")).toBe(false);
		expect(await bouncer.with("OrderPolicy").allows("listed")).toBe(true);
		// Roles are the user's, not the token's.
		expect(await bouncer.with("OrderPolicy").allows("admin")).toBe(true);
	});

	it("narrows the set AuthManager.resolvePermissions hands out", async () => {
		const { auth, user } = await setup(["orders:read"]);
		const effective = await auth.resolvePermissions(user);

		expect(effective.has("orders:delete")).toBe(false);
		expect([...effective.permissions]).toEqual(["orders:read"]);
	});

	it("a wildcard token keeps every permission of its user", async () => {
		const { auth, rights, user } = await setup(["*"]);
		const bouncer = await bouncerFor(auth, rights, user);

		expect(await bouncer.with("OrderPolicy").allows("delete")).toBe(true);
	});

	it("a token never widens: an ability the user lacks grants nothing", async () => {
		const { auth, rights, user } = await setup(["orders:read", "orders:purge"]);
		const bouncer = await bouncerFor(auth, rights, user);

		expect(await bouncer.with("OrderPolicy").allows("deleteAny")).toBe(false);
	});
});
