import "reflect-metadata";
import { describe, expect, it } from "vitest";
import {
	AuthManager,
	type AuthResult,
	type AuthStrategy,
} from "../../src/AuthManager.js";
import { Guard, Permission, Role } from "../../src/Guard.js";
import WardenMiddleware, {
	type WardenContext,
	wardenMiddleware,
} from "../../src/middleware.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import type { Scope } from "../../src/rights/types.js";

interface RecordedResponse {
	status?: number;
	body?: unknown;
}

interface BuildCtxOpts {
	headers?: Record<string, string>;
	manager: AuthManager;
	controller?: object;
	action?: string | symbol;
	session?: WardenContext["session"];
	registry?: {
		abilities: Record<string, unknown>;
		policies: Record<string, unknown>;
		resolveScope?: (ctx: WardenContext) => Scope | Promise<Scope>;
	};
}

function buildCtx(opts: BuildCtxOpts): {
	ctx: WardenContext;
	response: RecordedResponse;
	next: { called: boolean; fn: () => void };
} {
	// The middleware resolves AuthManager (+ optional bouncer:registry) from
	// `ctx.containerResolver` (Ream's per-request IoC resolver) — NOT from a
	// `@c9up/ream` import. Wire this test's instances into a fake resolver so
	// warden's tests stay agnostic and run standalone (no peer install needed).
	const bindings = new Map<unknown, unknown>();
	bindings.set(AuthManager, opts.manager);
	if (opts.registry) bindings.set("bouncer:registry", opts.registry);
	const containerResolver: WardenContext["containerResolver"] = {
		make(token) {
			if (bindings.has(token)) return bindings.get(token);
			// Mirror Ream's container: an unbound token throws (warden catches
			// and treats it as "not registered").
			throw new Error(`No binding for ${String(token)}`);
		},
	};

	const response: RecordedResponse = {};
	const next = {
		called: false,
		fn: () => {
			next.called = true;
		},
	};
	const headers = opts.headers ?? {};
	const ctx: WardenContext = {
		request: {
			headers: () => headers,
		},
		response: {
			status(code) {
				response.status = code;
			},
			json(data) {
				response.body = data;
			},
		},
		// Ream populates controller/action top-level on the HttpContext.
		controller: opts.controller,
		action: opts.action,
		session: opts.session,
		containerResolver,
	};
	return { ctx, response, next };
}

const okUser: AuthResult = {
	authenticated: true,
	user: {
		id: "u1",
		roles: ["admin", "editor"],
		permissions: ["orders.read", "orders.create"],
	},
};

/**
 * Inert stub used to satisfy AuthManager's no-empty-strategies invariant for
 * test cases that don't actually exercise authentication (public routes,
 * missing-controller paths). Both methods reject — these tests never reach
 * a verify() call site.
 */
const noopJwt: AuthStrategy = {
	name: "jwt",
	async authenticate() {
		return { authenticated: false, error: "stub" };
	},
	async verify() {
		return { authenticated: false, error: "stub" };
	},
};

function makeManager(strategies: Record<string, AuthStrategy>): AuthManager {
	// AuthManager now requires at least one strategy (boot-time fail-fast).
	// Tests that need a "no real auth" manager get the inert stub by default.
	const final =
		Object.keys(strategies).length === 0 ? { jwt: noopJwt } : strategies;
	return new AuthManager({ defaultStrategy: "jwt", strategies: final });
}

describe("warden > wardenMiddleware — public routes", () => {
	it("calls next() when no @Guard metadata is set on the route", async () => {
		const manager = makeManager({});
		const { ctx, next } = buildCtx({ manager });

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		expect(ctx.auth).toBeUndefined();
	});

	it("calls next() when route has no controller/action wired", async () => {
		const manager = makeManager({});
		const { ctx, next } = buildCtx({ manager, controller: undefined });

		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(true);
	});
});

describe("warden > wardenMiddleware — bearer token extraction", () => {
	const okJwtStrategy: AuthStrategy = {
		name: "jwt",
		async authenticate() {
			return { authenticated: false, error: "not used" };
		},
		async verify(token) {
			return token === "valid"
				? okUser
				: { authenticated: false, error: "bad" };
		},
	};

	class GuardedController {
		@Guard("jwt")
		async handler() {}
	}

	it("returns 401 when no token is provided and no session strategy is declared", async () => {
		const manager = makeManager({ jwt: okJwtStrategy });
		const { ctx, response, next } = buildCtx({
			manager,
			controller: GuardedController.prototype,
			action: "handler",
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(false);
		expect(response.status).toBe(401);
		expect(response.body).toMatchObject({ error: { code: "UNAUTHORIZED" } });
	});

	it("authenticates with a valid Bearer token", async () => {
		const manager = makeManager({ jwt: okJwtStrategy });
		const { ctx, response, next } = buildCtx({
			manager,
			controller: GuardedController.prototype,
			action: "handler",
			headers: { authorization: "Bearer valid" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		expect(response.status).toBeUndefined();
		expect(ctx.auth).toEqual(okUser);
	});

	it("rejects an invalid Bearer token with 401", async () => {
		const manager = makeManager({ jwt: okJwtStrategy });
		const { ctx, response, next } = buildCtx({
			manager,
			controller: GuardedController.prototype,
			action: "handler",
			headers: { authorization: "Bearer wrong" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(false);
		expect(response.status).toBe(401);
	});

	it("ignores a non-Bearer Authorization scheme", async () => {
		const manager = makeManager({ jwt: okJwtStrategy });
		const { ctx, response } = buildCtx({
			manager,
			controller: GuardedController.prototype,
			action: "handler",
			headers: { authorization: "Basic dXNlcjpwYXNz" },
		});

		await wardenMiddleware(ctx, () => {});
		expect(response.status).toBe(401);
	});

	it("rejects a token whose strategy reports it as revoked (E2E through the middleware)", async () => {
		// Wires a strategy whose verify() returns { authenticated:false } for
		// the second call — modelling a token blacklist hit. The first request
		// goes through; the second comes back with the SAME token but is
		// rejected with 401 by the middleware path (not just at strategy
		// level). Locks the wardenMiddleware behaviour to the revoke surface.
		let revoked = false;
		const blacklistStrategy: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				return { authenticated: false, error: "not used" };
			},
			async verify() {
				return revoked
					? { authenticated: false, error: "Token revoked" }
					: okUser;
			},
		};
		const manager = makeManager({ jwt: blacklistStrategy });

		const first = buildCtx({
			manager,
			controller: GuardedController.prototype,
			action: "handler",
			headers: { authorization: "Bearer abc" },
		});
		await wardenMiddleware(first.ctx, first.next.fn);
		expect(first.next.called).toBe(true);
		expect(first.response.status).toBeUndefined();

		revoked = true;

		const second = buildCtx({
			manager,
			controller: GuardedController.prototype,
			action: "handler",
			headers: { authorization: "Bearer abc" },
		});
		await wardenMiddleware(second.ctx, second.next.fn);
		expect(second.next.called).toBe(false);
		expect(second.response.status).toBe(401);
	});
});

describe("warden > wardenMiddleware — api-key extraction", () => {
	const okApiKeyStrategy: AuthStrategy & { headerName: string } = {
		name: "api-key",
		headerName: "x-custom-key",
		async authenticate() {
			return { authenticated: false, error: "not used" };
		},
		async verify(token) {
			return token === "k-good"
				? okUser
				: { authenticated: false, error: "bad key" };
		},
	};

	class ApiKeyController {
		@Guard("api-key")
		async handler() {}
	}

	it("uses the strategy's headerName to read the api-key", async () => {
		const manager = new AuthManager({
			defaultStrategy: "api-key",
			strategies: { "api-key": okApiKeyStrategy },
		});
		const { ctx, next } = buildCtx({
			manager,
			controller: ApiKeyController.prototype,
			action: "handler",
			headers: { "x-custom-key": "k-good" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		expect(ctx.auth).toEqual(okUser);
	});

	it("matches headerName case-insensitively (configured 'X-Custom-Key' → incoming 'x-custom-key')", async () => {
		// HTTP header names are case-insensitive; Node lowercases them.
		// Without normalisation, declaring `headerName: "X-Custom-Key"`
		// would silently break auth because the lookup wouldn't find
		// the lowercase header key the runtime delivers.
		const mixedCaseStrategy: AuthStrategy = {
			...okApiKeyStrategy,
			headerName: "X-Custom-Key",
		} as AuthStrategy & { headerName: string };

		const manager = new AuthManager({
			defaultStrategy: "api-key",
			strategies: { "api-key": mixedCaseStrategy },
		});
		const { ctx, next } = buildCtx({
			manager,
			controller: ApiKeyController.prototype,
			action: "handler",
			headers: { "x-custom-key": "k-good" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		expect(ctx.auth).toEqual(okUser);
	});

	it("falls back to 'x-api-key' when no api-key strategy is registered", async () => {
		const jwt: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				return { authenticated: false, error: "n/a" };
			},
			async verify(token) {
				return token === "valid"
					? okUser
					: { authenticated: false, error: "bad" };
			},
		};
		class JwtCtl {
			@Guard("jwt")
			async handler() {}
		}
		const manager = makeManager({ jwt });
		const { ctx, next } = buildCtx({
			manager,
			controller: JwtCtl.prototype,
			action: "handler",
			// No Authorization header — token comes through the default
			// 'x-api-key' fallback because no api-key strategy is registered.
			headers: { "x-api-key": "valid" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		expect(ctx.auth).toEqual(okUser);
	});
});

describe("warden > wardenMiddleware — strategy iteration", () => {
	const failingJwt: AuthStrategy = {
		name: "jwt",
		async authenticate() {
			return { authenticated: false, error: "no" };
		},
		async verify() {
			return { authenticated: false, error: "no" };
		},
	};

	const throwingApiKey: AuthStrategy = {
		name: "api-key",
		async authenticate() {
			throw new Error("boom");
		},
		async verify() {
			throw new Error("boom");
		},
	};

	it("tries multiple strategies and accepts the first that authenticates", async () => {
		const accepting: AuthStrategy = {
			name: "api-key",
			async authenticate() {
				return { authenticated: false, error: "n/a" };
			},
			async verify() {
				return okUser;
			},
		};
		const manager = makeManager({ jwt: failingJwt, "api-key": accepting });

		class MultiCtl {
			@Guard("jwt", "api-key")
			async handler() {}
		}
		const { ctx, next } = buildCtx({
			manager,
			controller: MultiCtl.prototype,
			action: "handler",
			headers: { authorization: "Bearer anything" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		expect(ctx.auth).toEqual(okUser);
	});

	it("swallows strategy throws and continues to the next strategy", async () => {
		const accepting: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				return { authenticated: false, error: "n/a" };
			},
			async verify() {
				return okUser;
			},
		};
		const manager = makeManager({ "api-key": throwingApiKey, jwt: accepting });

		class FallbackCtl {
			@Guard("api-key", "jwt")
			async handler() {}
		}
		const { ctx, next } = buildCtx({
			manager,
			controller: FallbackCtl.prototype,
			action: "handler",
			headers: { authorization: "Bearer x" },
		});

		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(true);
		expect(ctx.auth).toEqual(okUser);
	});

	it("returns 401 when every strategy rejects", async () => {
		const manager = makeManager({ jwt: failingJwt });
		class C {
			@Guard("jwt")
			async handler() {}
		}
		const { ctx, response, next } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer x" },
		});

		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(false);
		expect(response.status).toBe(401);
	});

	it("returns 500 with AUTH_STRATEGY_ERROR when EVERY attempted strategy throws", async () => {
		const throwingJwt: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				throw new Error("jwt secret missing");
			},
			async verify() {
				throw new Error("jwt secret missing");
			},
		};
		const manager = makeManager({
			"api-key": throwingApiKey,
			jwt: throwingJwt,
		});
		class C {
			@Guard("api-key", "jwt")
			async handler() {}
		}
		// Stub console.error so the loud log doesn't pollute the test output.
		const originalError = console.error;
		const captured: unknown[][] = [];
		console.error = (...args: unknown[]) => {
			captured.push(args);
		};
		try {
			const { ctx, response, next } = buildCtx({
				manager,
				controller: C.prototype,
				action: "handler",
				headers: { authorization: "Bearer x" },
			});

			await wardenMiddleware(ctx, next.fn);
			expect(next.called).toBe(false);
			expect(response.status).toBe(500);
			expect(response.body).toMatchObject({
				error: { code: "AUTH_STRATEGY_ERROR" },
			});
			// Both strategy crashes were logged (one per attempted strategy).
			expect(captured.length).toBe(2);
			expect(String(captured[0]?.[0])).toMatch(
				/\[warden\] strategy '(api-key|jwt)' threw/,
			);
		} finally {
			console.error = originalError;
		}
	});

	it("returns 401 (NOT 500) when one strategy throws but another rejects normally", async () => {
		const manager = makeManager({
			"api-key": throwingApiKey,
			jwt: failingJwt,
		});
		class C {
			@Guard("api-key", "jwt")
			async handler() {}
		}
		const originalError = console.error;
		console.error = () => {};
		try {
			const { ctx, response, next } = buildCtx({
				manager,
				controller: C.prototype,
				action: "handler",
				headers: { authorization: "Bearer x" },
			});

			await wardenMiddleware(ctx, next.fn);
			expect(next.called).toBe(false);
			// Mixed crash + rejection → not a clean server-side incident; 401 stands.
			expect(response.status).toBe(401);
		} finally {
			console.error = originalError;
		}
	});
});

describe("warden > wardenMiddleware — session strategy", () => {
	interface SessionLike {
		get(key: string): unknown;
	}

	const sessionStrategy = {
		name: "session",
		async authenticate() {
			return { authenticated: false, error: "use verifyWithContext" };
		},
		async verify() {
			return { authenticated: false, error: "use verifyWithContext" };
		},
		async verifyWithContext(_token: string, c: unknown) {
			const sess = (c as { session?: SessionLike }).session;
			if (!sess) return { authenticated: false, error: "no session" };
			const userId = sess.get("user_id");
			return typeof userId === "string"
				? { authenticated: true, user: { id: userId } }
				: { authenticated: false, error: "no session user" };
		},
	} satisfies AuthStrategy & {
		verifyWithContext(token: string, ctx: unknown): Promise<AuthResult>;
	};

	class SessionCtl {
		@Guard("session")
		async handler() {}
	}

	it("authenticates via session even without a token", async () => {
		const manager = new AuthManager({
			defaultStrategy: "session",
			strategies: { session: sessionStrategy },
		});
		const session: SessionLike = {
			get(key) {
				return key === "user_id" ? "u-session" : undefined;
			},
		};
		const { ctx, next } = buildCtx({
			manager,
			controller: SessionCtl.prototype,
			action: "handler",
			session,
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		expect(ctx.auth).toMatchObject({
			authenticated: true,
			user: { id: "u-session" },
		});
	});

	it("rejects with 401 when session strategy returns unauthenticated", async () => {
		const manager = new AuthManager({
			defaultStrategy: "session",
			strategies: { session: sessionStrategy },
		});
		const { ctx, response } = buildCtx({
			manager,
			controller: SessionCtl.prototype,
			action: "handler",
			session: { get: () => undefined },
		});

		await wardenMiddleware(ctx, () => {});
		expect(response.status).toBe(401);
	});

	it("sanitizes prototype-pollution keys from the session user (same guard as JWT path)", async () => {
		// The session path calls verifyWithContext directly, bypassing
		// AuthManager.verify()'s sanitizePayload. A hostile/buggy session
		// store returning a user with `__proto__`/`constructor` keys must
		// be scrubbed before it's attached to ctx.auth.
		const pollutingStrategy = {
			name: "session",
			async authenticate() {
				return { authenticated: false, error: "n/a" };
			},
			async verify() {
				return { authenticated: false, error: "n/a" };
			},
			async verifyWithContext(_t: string, _c: unknown) {
				const user = JSON.parse(
					'{"id":"u1","__proto__":{"polluted":true},"constructor":"x"}',
				);
				return { authenticated: true, user };
			},
		} satisfies AuthStrategy & {
			verifyWithContext(token: string, ctx: unknown): Promise<AuthResult>;
		};
		const manager = new AuthManager({
			defaultStrategy: "session",
			strategies: { session: pollutingStrategy },
		});
		const { ctx, next } = buildCtx({
			manager,
			controller: SessionCtl.prototype,
			action: "handler",
			session: { get: () => "u1" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(true);
		const user = Reflect.get(ctx.auth ?? {}, "user") ?? {};
		expect(Reflect.get(user, "id")).toBe("u1");
		// The dangerous own-key is stripped.
		expect(Object.hasOwn(user, "constructor")).toBe(false);
		// And Object.prototype was not polluted.
		expect(Reflect.get(Object.prototype, "polluted")).toBeUndefined();
	});

	it("skips session strategy when verifyWithContext is not implemented", async () => {
		const sessionWithoutCtx: AuthStrategy = {
			name: "session",
			async authenticate() {
				return { authenticated: false, error: "n/a" };
			},
			async verify() {
				return { authenticated: false, error: "n/a" };
			},
		};
		const manager = new AuthManager({
			defaultStrategy: "session",
			strategies: { session: sessionWithoutCtx },
		});
		const { ctx, response } = buildCtx({
			manager,
			controller: SessionCtl.prototype,
			action: "handler",
		});

		await wardenMiddleware(ctx, () => {});
		expect(response.status).toBe(401);
	});
});

describe("warden > wardenMiddleware — permission and role checks", () => {
	const acceptStrategy: AuthStrategy = {
		name: "jwt",
		async authenticate() {
			return { authenticated: false, error: "n/a" };
		},
		async verify() {
			return okUser;
		},
	};

	it("returns 403 with the missing permissions list", async () => {
		class C {
			@Guard("jwt")
			@Permission("orders.delete")
			async handler() {}
		}
		const manager = makeManager({ jwt: acceptStrategy });
		const { ctx, response, next } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(false);
		expect(response.status).toBe(403);
		expect(response.body).toMatchObject({ error: { code: "FORBIDDEN" } });
	});

	it("authorizes when the resolved set covers all required permissions", async () => {
		class C {
			@Guard("jwt")
			@Permission("orders.read")
			async handler() {}
		}
		// D1: token permissions are ignored — the resolved set is the source of
		// truth, so seed a role granting orders.read for u1 (okUser.user.id).
		const store = new MemoryRightsStore()
			.defineRole("reader", ["orders.read"])
			.assignRole("u1", "reader");
		const manager = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: acceptStrategy },
			rights: new RightsResolver(store),
		});
		const { ctx, next } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
		});

		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(true);
	});

	it("@Permission gate resolves at the registry-resolved tenant scope, not hardcoded global (audit 2026-06-13)", async () => {
		class C {
			@Guard("jwt")
			@Permission("orders.read")
			async handler() {}
		}
		// orders.read is granted ONLY at tenant:acme (NOT global). Pre-fix the gate
		// resolved "global" → empty set → 403; honoring resolveScope it must pass.
		const store = new MemoryRightsStore()
			.defineRole("reader", ["orders.read"], { tenant: "acme" })
			.assignRole("u1", "reader", { tenant: "acme" });
		const manager = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: acceptStrategy },
			rights: new RightsResolver(store),
		});
		const { ctx, next } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
			registry: {
				abilities: {},
				policies: {},
				resolveScope: () => ({ tenant: "acme" }),
			},
		});

		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(true);
	});

	it("does NOT honour token permissions at the gate — 403 even though the token lists it (D1)", async () => {
		// okUser carries permissions: ["orders.read", "orders.create"] in the
		// token. With an empty store the resolved set is empty, so a token-only
		// permission must NOT pass the gate (the second-authority leak the epic
		// deletes — AC10 probe 1/2).
		class C {
			@Guard("jwt")
			@Permission("orders.read")
			async handler() {}
		}
		const manager = makeManager({ jwt: acceptStrategy });
		const { ctx, response, next } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
		});

		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(false);
		expect(response.status).toBe(403);
		expect(response.body).toMatchObject({ error: { code: "FORBIDDEN" } });
	});

	it("authorizes a role-gated route via payload roles with no store config (D2)", async () => {
		// Roles ARE a resolver input (payload ∪ store) — okUser carries
		// roles: ["admin", "editor"], so an @Role("admin") route passes with a
		// default empty store (existing consumers keep working — AC-E6).
		class C {
			@Guard("jwt")
			@Role("admin")
			async handler() {}
		}
		const manager = makeManager({ jwt: acceptStrategy });
		const { ctx, next } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
		});

		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(true);
	});

	it("returns 403 with the missing roles list", async () => {
		class C {
			@Guard("jwt")
			@Role("superadmin")
			async handler() {}
		}
		const manager = makeManager({ jwt: acceptStrategy });
		const { ctx, response } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
		});

		await wardenMiddleware(ctx, () => {});

		expect(response.status).toBe(403);
		expect(response.body).toMatchObject({ error: { code: "FORBIDDEN" } });
	});

	it("requires both permissions AND roles when both are declared (AND gate, not OR)", async () => {
		class C {
			@Guard("jwt")
			@Permission("orders.read")
			@Role("superadmin")
			async handler() {}
		}
		const manager = makeManager({ jwt: acceptStrategy });
		const { ctx, response, next } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
		});

		await wardenMiddleware(ctx, next.fn);

		expect(next.called).toBe(false);
		expect(response.status).toBe(403);
	});

	it("treats an authenticated user without permissions array as having none", async () => {
		const accept: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				return { authenticated: false, error: "n/a" };
			},
			async verify() {
				return { authenticated: true, user: { id: "u-bare" } };
			},
		};
		class C {
			@Guard("jwt")
			@Permission("orders.read")
			async handler() {}
		}
		const manager = makeManager({ jwt: accept });
		const { ctx, response } = buildCtx({
			manager,
			controller: C.prototype,
			action: "handler",
			headers: { authorization: "Bearer ok" },
		});

		await wardenMiddleware(ctx, () => {});
		expect(response.status).toBe(403);
	});
});

describe("warden > Ream ctx integration (regression)", () => {
	class SecureController {
		@Guard("jwt")
		secret() {}
	}

	it("default export is a class with handle() — Ream lazy router.use resolver", () => {
		// Ream does `new mod.default().handle(ctx, next)` for the documented
		// router.use([() => import('@c9up/warden/middleware')]) form.
		expect(typeof WardenMiddleware).toBe("function");
		expect(typeof new WardenMiddleware().handle).toBe("function");
	});

	it("enforces a guarded route read from ctx.controller/action — no fail-open", async () => {
		// SECURITY: guard metadata must come from ctx.controller/ctx.action (Ream's
		// shape). If misread, getGuardMetadata returns [] → route treated as public
		// → auth bypass. A guarded route with no token must 401, not pass through.
		const { ctx, response, next } = buildCtx({
			manager: makeManager({}),
			controller: SecureController.prototype,
			action: "secret",
			headers: {},
		});
		await wardenMiddleware(ctx, next.fn);
		expect(next.called).toBe(false);
		expect(response.status).toBe(401);
	});
});
