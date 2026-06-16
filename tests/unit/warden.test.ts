import "reflect-metadata";
import { describe, expect, it } from "vitest";
import type { AuthStrategy, JwtClaims, UserPayload } from "../../src/index.js";
import {
	ApiKeyStrategy,
	AuthManager,
	AuthRateLimiter,
	Guard,
	getGuardMetadata,
	getPermissionMetadata,
	getRoleMetadata,
	JwtStrategy,
	MemoryBlacklistDriver,
	Permission,
	Role,
	TokenBlacklist,
} from "../../src/index.js";

// === Mock strategies ===

const mockJwtStrategy: AuthStrategy = {
	name: "jwt",
	async authenticate(creds) {
		if (creds.email === "admin@c9up.com" && creds.password === "secret") {
			return {
				authenticated: true,
				user: {
					id: "1",
					roles: ["admin"],
					permissions: ["orders.create", "orders.read"],
				},
			};
		}
		return { authenticated: false, error: "Invalid credentials" };
	},
	async verify(token) {
		if (token === "valid-jwt-token") {
			return { authenticated: true, user: { id: "1", roles: ["admin"] } };
		}
		return { authenticated: false, error: "Invalid token" };
	},
};

const mockSessionStrategy: AuthStrategy = {
	name: "session",
	async authenticate() {
		return { authenticated: true, user: { id: "2" } };
	},
	async verify(token) {
		return token === "session-id"
			? { authenticated: true, user: { id: "2" } }
			: { authenticated: false, error: "Invalid session" };
	},
};

const throwingStrategy: AuthStrategy = {
	name: "throwing",
	async authenticate() {
		throw new Error("Network timeout");
	},
	async verify() {
		throw new Error("Connection refused");
	},
};

describe("warden > AuthManager", () => {
	it("authenticates with default strategy", async () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy },
		});
		const result = await auth.authenticate({
			email: "admin@c9up.com",
			password: "secret",
		});
		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe("1");
	});

	it("rejects invalid credentials", async () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy },
		});
		const result = await auth.authenticate({
			email: "wrong",
			password: "wrong",
		});
		expect(result.authenticated).toBe(false);
		expect(result.error).toBe("Invalid credentials");
	});

	it("verifies token", async () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy },
		});
		expect((await auth.verify("valid-jwt-token")).authenticated).toBe(true);
		expect((await auth.verify("invalid")).authenticated).toBe(false);
	});

	it("uses named strategy", async () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy, session: mockSessionStrategy },
		});
		const result = await auth.verify("session-id", "session");
		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe("2");
	});

	it("constructor THROWS INVALID_CONFIG when strategies is empty (boot-time fail-fast)", () => {
		// Was: silently constructed an AuthManager that crashed on first
		// getStrategy() call. Now an empty registry is a config bug caught
		// at construction so the operator gets a clear actionable boot error.
		expect(
			() => new AuthManager({ defaultStrategy: "jwt", strategies: {} }),
		).toThrow(/INVALID_CONFIG|no authentication strategies registered/);
	});

	it("throws on unknown strategy lookup against a populated registry", () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy },
		});
		expect(() => auth.getStrategy("nonexistent")).toThrow("Auth strategy");
	});

	it("catches strategy exceptions on authenticate", async () => {
		const auth = new AuthManager({
			defaultStrategy: "throwing",
			strategies: { throwing: throwingStrategy },
		});
		const result = await auth.authenticate({ email: "test" });
		expect(result.authenticated).toBe(false);
		expect(result.error).toBe("Network timeout");
	});

	it("catches strategy exceptions on verify", async () => {
		const auth = new AuthManager({
			defaultStrategy: "throwing",
			strategies: { throwing: throwingStrategy },
		});
		const result = await auth.verify("some-token");
		expect(result.authenticated).toBe(false);
		expect(result.error).toBe("Connection refused");
	});
});

describe("warden > RBAC", () => {
	// `permissions` is carried in the token payload but is NOT a resolver input
	// (D1) — the coarse helpers consult the resolved set only.
	const user: UserPayload = {
		id: "1",
		roles: ["admin", "editor"],
		permissions: ["orders.create", "orders.read", "users.list"],
	};

	it("checks role from payload ∪ store — token roles still satisfy it (D2)", async () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy },
		});
		expect(await auth.hasRole(user, "admin")).toBe(true);
		expect(await auth.hasRole(user, "superadmin")).toBe(false);
	});

	it("does NOT honour token permissions — coarse @Permission reads the resolved set only (D1)", async () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy },
		});
		// In the token payload, but unseeded in the (default empty) store ⇒ false.
		expect(await auth.hasPermission(user, "orders.create")).toBe(false);
		expect(await auth.hasPermission(user, "orders.delete")).toBe(false);
		expect(
			await auth.hasAllPermissions(user, ["orders.create", "orders.read"]),
		).toBe(false);
	});

	it("hasAllPermissions returns true for empty array (vacuous truth)", async () => {
		const auth = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: mockJwtStrategy },
		});
		expect(await auth.hasAllPermissions(user, [])).toBe(true);
	});
});

describe("warden > decorators", () => {
	class TestController {
		@Guard("jwt")
		@Permission("orders.create")
		@Role("admin")
		async createOrder() {}

		@Guard("jwt", "session")
		async multiGuard() {}
	}

	it("@Guard stores strategy names via Symbol.for", () => {
		const guards = getGuardMetadata(TestController.prototype, "createOrder");
		expect(guards).toEqual(["jwt"]);
	});

	it("@Guard supports multiple strategies", () => {
		const guards = getGuardMetadata(TestController.prototype, "multiGuard");
		expect(guards).toEqual(["jwt", "session"]);
	});

	it("@Permission stores permissions", () => {
		const perms = getPermissionMetadata(
			TestController.prototype,
			"createOrder",
		);
		expect(perms).toEqual(["orders.create"]);
	});

	it("@Role stores roles", () => {
		const roles = getRoleMetadata(TestController.prototype, "createOrder");
		expect(roles).toEqual(["admin"]);
	});

	it("metadata is accessible via Symbol.for directly", () => {
		const guards = Reflect.getOwnMetadata(
			Symbol.for("warden:guard"),
			TestController.prototype,
			"createOrder",
		);
		expect(guards).toEqual(["jwt"]);
	});
});

describe("warden > security hardening", () => {
	it("JwtStrategy rejects payloads with non-string sub", async () => {
		const jwt = new JwtStrategy({
			secret: "x".repeat(32),
			findUser: async () => ({ id: "1" }),
			verifyCredentials: async () => null,
		});

		// Header/payload signed with same secret but invalid "sub" type.
		const header = Buffer.from(
			JSON.stringify({ alg: "HS256", typ: "JWT" }),
		).toString("base64url");
		const payload = Buffer.from(
			JSON.stringify({
				sub: { id: 1 },
				exp: Math.floor(Date.now() / 1000) + 3600,
			}),
		).toString("base64url");
		const crypto = await import("node:crypto");
		const sig = crypto
			.createHmac("sha256", "x".repeat(32))
			.update(`${header}.${payload}`)
			.digest("base64url");
		const token = `${header}.${payload}.${sig}`;

		const result = await jwt.verify(token);
		expect(result.authenticated).toBe(false);
	});

	it("JwtStrategy passes the full verified claims (sub/iat/jti) to findUser", async () => {
		let seen: JwtClaims | undefined;
		const jwt = new JwtStrategy({
			secret: "x".repeat(32),
			findUser: async (id, claims) => {
				seen = claims;
				return { id };
			},
			verifyCredentials: async () => null,
		});
		const token = jwt.signToken({ id: "u1" });
		const res = await jwt.verify(token);
		expect(res.authenticated).toBe(true);
		expect(seen?.sub).toBe("u1");
		expect(typeof seen?.iat).toBe("number");
		expect(typeof seen?.jti).toBe("string");
	});

	it("findUser can reject a stale token via claims (iat < passwordChangedAt) — session invalidation", async () => {
		// Simulate "password changed after this token was issued": the app
		// compares the token's iat to a stored passwordChangedAt and rejects.
		// Before claims were passed to findUser this was impossible (audit 2026-06-15).
		const passwordChangedAt = Math.floor(Date.now() / 1000) + 1000;
		const jwt = new JwtStrategy({
			secret: "x".repeat(32),
			findUser: async (id, claims) =>
				claims.iat < passwordChangedAt ? null : { id },
			verifyCredentials: async () => null,
		});
		const token = jwt.signToken({ id: "u1" }); // iat = now < passwordChangedAt
		const res = await jwt.verify(token);
		expect(res.authenticated).toBe(false);
	});

	it("JwtStrategy.revoke makes a previously-valid token unverifiable", async () => {
		const blacklist = new TokenBlacklist(new MemoryBlacklistDriver());
		const jwt = new JwtStrategy({
			secret: "x".repeat(32),
			findUser: async (id) => ({ id }),
			verifyCredentials: async (email, password) =>
				email === "a@b.c" && password === "p" ? { id: "u1" } : null,
			blacklist,
		});

		const auth = await jwt.authenticate({ email: "a@b.c", password: "p" });
		expect(auth.authenticated).toBe(true);
		const token = auth.user?.token;
		expect(typeof token).toBe("string");
		if (typeof token !== "string") return;

		// Token verifies before revocation.
		const before = await jwt.verify(token);
		expect(before.authenticated).toBe(true);

		const revoked = await jwt.revoke(token);
		expect(revoked).toBe(true);

		const after = await jwt.verify(token);
		expect(after.authenticated).toBe(false);
		expect(after.error).toBe("Token revoked");
	});

	it("JwtStrategy.verify rejects a (validly-signed) token with no jti when a blacklist is configured", async () => {
		// A token signed with the right secret but missing `jti` cannot be
		// checked for revocation — isRevoked(undefined) always returns
		// false, so it would be permanently unrevocable. With a blacklist
		// configured we must reject it, not let an unrevocable token in.
		const { createHmac } = await import("node:crypto");
		const secret = "x".repeat(32);
		const b64u = (o: object) =>
			Buffer.from(JSON.stringify(o)).toString("base64url");
		const now = Math.floor(Date.now() / 1000);
		const head = b64u({ alg: "HS256", typ: "JWT" });
		// Payload deliberately omits `jti`.
		const body = b64u({ sub: "u1", iat: now, exp: now + 3600 });
		const sig = createHmac("sha256", secret)
			.update(`${head}.${body}`)
			.digest("base64url");
		const forged = `${head}.${body}.${sig}`;

		const jwt = new JwtStrategy({
			secret,
			findUser: async (id) => ({ id }),
			verifyCredentials: async () => null,
			blacklist: new TokenBlacklist(new MemoryBlacklistDriver()),
		});
		const res = await jwt.verify(forged);
		expect(res.authenticated).toBe(false);
		expect(res.error).toBe("Token missing jti claim");
	});

	it("JwtStrategy.verify accepts a no-jti token when NO blacklist is configured", async () => {
		// Without revocation there's nothing to check, so a missing jti is
		// harmless — the token verifies on signature + sub as before.
		const { createHmac } = await import("node:crypto");
		const secret = "y".repeat(32);
		const b64u = (o: object) =>
			Buffer.from(JSON.stringify(o)).toString("base64url");
		const now = Math.floor(Date.now() / 1000);
		const head = b64u({ alg: "HS256", typ: "JWT" });
		const body = b64u({ sub: "u2", iat: now, exp: now + 3600 });
		const sig = createHmac("sha256", secret)
			.update(`${head}.${body}`)
			.digest("base64url");
		const forged = `${head}.${body}.${sig}`;

		const jwt = new JwtStrategy({
			secret,
			findUser: async (id) => ({ id }),
			verifyCredentials: async () => null,
		});
		const res = await jwt.verify(forged);
		expect(res.authenticated).toBe(true);
		expect(res.user?.id).toBe("u2");
	});

	it("JwtStrategy.revoke throws without a blacklist driver", async () => {
		const jwt = new JwtStrategy({
			secret: "x".repeat(32),
			findUser: async (id) => ({ id }),
			verifyCredentials: async () => ({ id: "u1" }),
		});
		const auth = await jwt.authenticate({ email: "a@b.c", password: "p" });
		const token = auth.user?.token ?? "";
		await expect(jwt.revoke(token)).rejects.toThrow(/blacklist/);
	});

	it("JwtStrategy verifies tokens signed with a previousSecret during rotation", async () => {
		const SECRET_OLD = "a".repeat(32);
		const SECRET_NEW = "b".repeat(32);

		// Pre-rotation: app signs with SECRET_OLD.
		const before = new JwtStrategy({
			secret: SECRET_OLD,
			findUser: async (id) => ({ id }),
			verifyCredentials: async () => ({ id: "u1" }),
		});
		const tokenOld = before.signToken({ id: "u1" });

		// Post-rotation: app signs with SECRET_NEW, still accepts SECRET_OLD
		// during the rotation window.
		const after = new JwtStrategy({
			secret: SECRET_NEW,
			previousSecrets: [SECRET_OLD],
			findUser: async (id) => ({ id }),
			verifyCredentials: async () => ({ id: "u1" }),
		});

		// Old token verifies (signed with SECRET_OLD, accepted via rotation).
		const verifyOld = await after.verify(tokenOld);
		expect(verifyOld.authenticated).toBe(true);

		// New token signs with SECRET_NEW + verifies trivially.
		const tokenNew = after.signToken({ id: "u1" });
		const verifyNew = await after.verify(tokenNew);
		expect(verifyNew.authenticated).toBe(true);

		// After full rotation (drop previousSecrets), old tokens stop working.
		const dropped = new JwtStrategy({
			secret: SECRET_NEW,
			findUser: async (id) => ({ id }),
			verifyCredentials: async () => ({ id: "u1" }),
		});
		const rejected = await dropped.verify(tokenOld);
		expect(rejected.authenticated).toBe(false);
	});

	it("JwtStrategy rejects previousSecrets shorter than 32 chars", () => {
		expect(
			() =>
				new JwtStrategy({
					secret: "x".repeat(32),
					previousSecrets: ["short"],
					findUser: async (id) => ({ id }),
					verifyCredentials: async () => null,
				}),
		).toThrow(/previousSecrets/);
	});

	it("JwtStrategy emits a unique jti on every signToken", async () => {
		const jwt = new JwtStrategy({
			secret: "x".repeat(32),
			findUser: async (id) => ({ id }),
			verifyCredentials: async () => ({ id: "u1" }),
		});
		const t1 = jwt.signToken({ id: "u1" });
		const t2 = jwt.signToken({ id: "u1" });
		const decode = (jwt: string) =>
			JSON.parse(
				Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"),
			) as { jti: string };
		const j1 = decode(t1).jti;
		const j2 = decode(t2).jti;
		expect(typeof j1).toBe("string");
		expect(j1).not.toBe(j2);
	});

	it("ApiKeyStrategy does not mutate source user and deduplicates permissions", async () => {
		const sourceUser = { id: "u1", permissions: ["users.read"] };
		const apiKey = new ApiKeyStrategy({
			findByKey: async () => ({
				user: sourceUser,
				scopes: ["users.read", "users.write"],
			}),
		});

		const result = await apiKey.verify("k");
		expect(result.authenticated).toBe(true);
		expect(result.user?.permissions).toEqual(["users.read", "users.write"]);
		expect(sourceUser.permissions).toEqual(["users.read"]);
	});

	it("AuthRateLimiter normalizes identifier case/spacing", () => {
		const limiter = new AuthRateLimiter({ maxAttempts: 2, windowSeconds: 60 });
		limiter.recordFailure("127.0.0.1", "  USER@EXAMPLE.COM ");
		expect(limiter.check("127.0.0.1", "user@example.com")).toBe(true);
		limiter.recordFailure("127.0.0.1", "user@example.com");
		expect(limiter.check("127.0.0.1", "USER@example.com")).toBe(false);
	});
});

describe("warden > AuthManager.issueFor", () => {
	function claims(token: string): Record<string, unknown> {
		const part = token.split(".")[1];
		return JSON.parse(Buffer.from(part, "base64url").toString());
	}

	const user: UserPayload = {
		id: "u1",
		roles: ["admin"],
		permissions: ["posts:write"],
	};

	it("mints a token whose claims match the authenticate() path (no bcrypt)", async () => {
		const jwt = new JwtStrategy({
			secret: "x".repeat(32),
			findUser: async (id) => ({ id }),
			// authenticate() resolves the same user via verifyCredentials
			verifyCredentials: async () => user,
		});
		const mgr = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt },
		});

		const issued = mgr.issueFor(user);
		const authed = await mgr.authenticate({
			email: "a@b.com",
			password: "pw",
		});

		// Same claim SHAPE as authenticate() (iat/jti differ per call).
		const i = claims(issued);
		const a = claims(authed.user?.token as string);
		expect(i.sub).toBe("u1");
		expect(i.roles).toEqual(["admin"]);
		expect(i.permissions).toEqual(["posts:write"]);
		expect(i.sub).toBe(a.sub);
		expect(i.roles).toEqual(a.roles);
		expect(i.permissions).toEqual(a.permissions);

		// And the minted token actually verifies.
		const verified = await mgr.verify(issued);
		expect(verified.authenticated).toBe(true);
		expect(verified.user?.id).toBe("u1");
	});

	it("throws STRATEGY_CANNOT_ISSUE for a strategy that can't mint tokens", () => {
		const fake: AuthStrategy = {
			name: "fake",
			authenticate: async () => ({ authenticated: false }),
			verify: async () => ({ authenticated: false }),
		};
		const mgr = new AuthManager({
			defaultStrategy: "fake",
			strategies: { fake },
		});
		expect(() => mgr.issueFor(user)).toThrow(/cannot issue tokens/);
	});
});
