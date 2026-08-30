import "reflect-metadata";
import { describe, expect, it, vi } from "vitest";
import { Authenticator } from "../../src/Authenticator.js";
import {
	AuthManager,
	type AuthResult,
	type AuthStrategy,
	type UserPayload,
} from "../../src/AuthManager.js";
import {
	E_INVALID_CREDENTIALS,
	E_UNAUTHORIZED_ACCESS,
} from "../../src/errors.js";
import { Guard } from "../../src/Guard.js";
import {
	renderAuthError,
	type WardenContext,
	wardenMiddleware,
} from "../../src/middleware.js";
import { MemoryRememberMeTokenDriver } from "../../src/RememberMeToken.js";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";

const okUser: UserPayload = { id: "u1", roles: ["admin"] };

/** jwt guard that authenticates exactly the token "good". */
const jwtStub: AuthStrategy = {
	name: "jwt",
	async authenticate() {
		return { authenticated: false, error: "n/a" };
	},
	async verify(token) {
		return token === "good"
			? { authenticated: true, user: okUser }
			: { authenticated: false, error: "bad token" };
	},
};

function fakeSession(store: Record<string, unknown> = {}): SessionStore & {
	store: Record<string, unknown>;
	regenerated: boolean;
} {
	return {
		store,
		regenerated: false,
		get(key) {
			return store[key];
		},
		put(key, value) {
			store[key] = value;
		},
		forget(key) {
			delete store[key];
		},
		regenerate() {
			this.regenerated = true;
		},
	};
}

interface CtxOpts {
	manager: AuthManager;
	headers?: Record<string, string>;
	session?: SessionStore;
	loginRoute?: string;
	controller?: object;
	action?: string | symbol;
}

function buildCtx(opts: CtxOpts): {
	ctx: WardenContext;
	response: { status?: number; body?: unknown; redirectedTo?: string };
} {
	const bindings = new Map<unknown, unknown>();
	bindings.set(AuthManager, opts.manager);
	if (opts.loginRoute !== undefined)
		bindings.set("warden:loginRoute", opts.loginRoute);
	const response: { status?: number; body?: unknown; redirectedTo?: string } =
		{};
	const ctx: WardenContext = {
		request: { headers: () => opts.headers ?? {} },
		response: {
			status(code) {
				response.status = code;
			},
			json(data) {
				response.body = data;
			},
			redirect(url) {
				response.redirectedTo = url;
			},
		},
		session: opts.session,
		route: { controller: opts.controller, action: opts.action },
		containerResolver: {
			async make(token) {
				if (bindings.has(token)) return bindings.get(token);
				throw new Error(`No binding for ${String(token)}`);
			},
		},
	};
	return { ctx, response };
}

describe("warden > Authenticator (#1) — inline-route contract", () => {
	it("authenticate() sets the user via the default guard", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		const { ctx } = buildCtx({
			manager,
			headers: { authorization: "Bearer good" },
		});
		const auth = new Authenticator(ctx, manager);

		await auth.authenticate();

		expect(auth.isAuthenticated).toBe(true);
		expect(auth.user?.id).toBe("u1");
		expect(auth.authenticationAttempted).toBe(true);
		expect(auth.authenticatedViaGuard).toBe("jwt");
	});

	it("authenticate() throws E_UNAUTHORIZED_ACCESS on a bad credential", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		const { ctx } = buildCtx({
			manager,
			headers: { authorization: "Bearer nope" },
		});
		const auth = new Authenticator(ctx, manager);

		await expect(auth.authenticate()).rejects.toBeInstanceOf(
			E_UNAUTHORIZED_ACCESS,
		);
		expect(auth.isAuthenticated).toBe(false);
	});

	it("check() returns a boolean and never throws on rejection", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		const good = new Authenticator(
			buildCtx({ manager, headers: { authorization: "Bearer good" } }).ctx,
			manager,
		);
		const bad = new Authenticator(
			buildCtx({ manager, headers: { authorization: "Bearer bad" } }).ctx,
			manager,
		);

		await expect(good.check()).resolves.toBe(true);
		await expect(bad.check()).resolves.toBe(false);
	});

	it("checkUsing() is the non-throwing sibling of authenticateUsing()", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		const good = new Authenticator(
			buildCtx({ manager, headers: { authorization: "Bearer good" } }).ctx,
			manager,
		);
		const bad = new Authenticator(
			buildCtx({ manager, headers: { authorization: "Bearer bad" } }).ctx,
			manager,
		);

		// A handler branching on "is anyone signed in through either of these"
		// had to wrap the throwing form in its own try/catch.
		await expect(good.checkUsing(["jwt"])).resolves.toBe(true);
		await expect(bad.checkUsing(["jwt"])).resolves.toBe(false);
	});

	it("checkUsing() still propagates a strategy crash", async () => {
		const crashing: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				return { authenticated: false };
			},
			async verify() {
				throw new Error("db down");
			},
		};
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: crashing },
		});
		const auth = new Authenticator(
			buildCtx({ manager, headers: { authorization: "Bearer x" } }).ctx,
			manager,
		);

		// A crashed strategy is a server problem, not "not signed in".
		await expect(auth.checkUsing(["jwt"])).rejects.toBeTruthy();
	});

	it("check() still propagates a strategy crash (not swallowed as guest)", async () => {
		const crashing: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				return { authenticated: false };
			},
			async verify() {
				throw new Error("db down");
			},
		};
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: crashing },
		});
		const { ctx } = buildCtx({
			manager,
			headers: { authorization: "Bearer x" },
		});
		vi.spyOn(console, "error").mockImplementation(() => {});
		const auth = new Authenticator(ctx, manager);
		await expect(auth.check()).rejects.toThrow(/Authentication unavailable/);
		vi.restoreAllMocks();
	});

	it("authenticateUsing() tries guards in order and stops at the first success", async () => {
		const failing: AuthStrategy = {
			name: "jwt",
			async authenticate() {
				return { authenticated: false };
			},
			async verify() {
				return { authenticated: false, error: "no" };
			},
		};
		const accepting: AuthStrategy = {
			name: "access_tokens",
			async authenticate() {
				return { authenticated: false };
			},
			async verify() {
				return { authenticated: true, user: okUser };
			},
		};
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: failing, access_tokens: accepting },
		});
		const { ctx } = buildCtx({
			manager,
			headers: { authorization: "Bearer anything" },
		});
		const auth = new Authenticator(ctx, manager);

		await auth.authenticateUsing(["jwt", "access_tokens"]);
		expect(auth.authenticatedViaGuard).toBe("access_tokens");
	});

	it("getUserOrFail() throws when unauthenticated, returns the user after auth", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		const { ctx } = buildCtx({
			manager,
			headers: { authorization: "Bearer good" },
		});
		const auth = new Authenticator(ctx, manager);

		expect(() => auth.getUserOrFail()).toThrow(E_UNAUTHORIZED_ACCESS);
		await auth.authenticate();
		expect(auth.getUserOrFail().id).toBe("u1");
	});
});

describe("warden > login()/logout() (#2, bug-3261)", () => {
	it("AuthManager.login rotates the session and stores the user id", async () => {
		const session = new SessionStrategy({ findUser: async () => okUser });
		const manager = new AuthManager({
			default: "session",
			guards: { session },
		});
		const store = fakeSession();
		await manager.login(okUser, store, "session");
		expect(store.regenerated).toBe(true);
		expect(store.store.auth_user_id).toBe("u1");
	});

	it("AuthManager.logout clears the session user id", async () => {
		const session = new SessionStrategy({ findUser: async () => okUser });
		const manager = new AuthManager({
			default: "session",
			guards: { session },
		});
		const store = fakeSession({ auth_user_id: "u1" });
		await manager.logout(store, "session");
		expect(store.store.auth_user_id).toBeUndefined();
	});

	it("ctx.auth.use('session').login(user) works (Adonis auth.use('web').login)", async () => {
		const session = new SessionStrategy({ findUser: async () => okUser });
		const manager = new AuthManager({
			default: "session",
			guards: { session },
		});
		const store = fakeSession();
		const { ctx } = buildCtx({ manager, session: store });
		const auth = new Authenticator(ctx, manager);

		await auth.use("session").login(okUser);
		expect(store.store.auth_user_id).toBe("u1");
	});

	it("login through a stateless (jwt) guard throws STRATEGY_CANNOT_LOGIN", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		const store = fakeSession();
		await expect(manager.login(okUser, store, "jwt")).rejects.toThrow(
			/does not support session login/,
		);
	});
});

describe("warden > config guards form (#5)", () => {
	it("AuthManager accepts the AdonisJS { default, guards } form", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		expect(manager.defaultStrategyName).toBe("jwt");
		expect(manager.getStrategyNames()).toContain("jwt");
	});

	it("AuthManager still accepts the legacy { defaultStrategy, strategies } form", () => {
		const manager = new AuthManager({
			defaultStrategy: "jwt",
			strategies: { jwt: jwtStub },
		});
		expect(manager.defaultStrategyName).toBe("jwt");
	});
});

describe("warden > access_tokens guard rename (#11)", () => {
	it("ApiKeyStrategy.name is 'access_tokens'", async () => {
		const { ApiKeyStrategy } = await import(
			"../../src/strategies/ApiKeyStrategy.js"
		);
		const strat = new ApiKeyStrategy({ findByKey: async () => null });
		expect(strat.name).toBe("access_tokens");
	});
});

describe("warden > E_UNAUTHORIZED_ACCESS rendering (#6)", () => {
	class SessionCtl {
		@Guard("session")
		async handler() {}
	}

	function sessionManager(): AuthManager {
		const session: AuthStrategy & {
			verifyWithContext(t: string, c: unknown): Promise<AuthResult>;
		} = {
			name: "session",
			async authenticate() {
				return { authenticated: false };
			},
			async verify() {
				return { authenticated: false };
			},
			async verifyWithContext() {
				return { authenticated: false, error: "no session user" };
			},
		};
		return new AuthManager({ default: "session", guards: { session } });
	}

	it("redirects an HTML client to loginRoute for a failed session guard", async () => {
		const manager = sessionManager();
		const { ctx, response } = buildCtx({
			manager,
			controller: SessionCtl.prototype,
			action: "handler",
			session: fakeSession(),
			loginRoute: "/login",
			headers: { accept: "text/html" },
		});

		await wardenMiddleware(ctx, async () => {});

		expect(response.redirectedTo).toBe("/login");
		expect(response.status).toBeUndefined();
	});

	it("returns 401 JSON with code E_UNAUTHORIZED_ACCESS for a JSON client", async () => {
		const manager = sessionManager();
		const { ctx, response } = buildCtx({
			manager,
			controller: SessionCtl.prototype,
			action: "handler",
			session: fakeSession(),
			loginRoute: "/login",
			headers: { accept: "application/json" },
		});

		await wardenMiddleware(ctx, async () => {});

		expect(response.redirectedTo).toBeUndefined();
		expect(response.status).toBe(401);
		expect(response.body).toMatchObject({
			error: { code: "E_UNAUTHORIZED_ACCESS" },
		});
	});

	it("renderAuthError falls back to 401 JSON when no redirect target", () => {
		const { ctx, response } = buildCtx({
			manager: new AuthManager({ default: "jwt", guards: { jwt: jwtStub } }),
			headers: { accept: "text/html" },
		});
		renderAuthError(
			ctx,
			new E_UNAUTHORIZED_ACCESS("nope", { guardDriverName: "jwt" }),
		);
		expect(response.status).toBe(401);
		expect(response.redirectedTo).toBeUndefined();
	});

	it("E_INVALID_CREDENTIALS exposes the bare Adonis code and 400 status", () => {
		const err = new E_INVALID_CREDENTIALS();
		expect(err.code).toBe("E_INVALID_CREDENTIALS");
		expect(err.status).toBe(400);
	});

	it("E_UNAUTHORIZED_ACCESS exposes the bare Adonis code (no WARDEN_ prefix)", () => {
		const err = new E_UNAUTHORIZED_ACCESS("x", { guardDriverName: "session" });
		expect(err.code).toBe("E_UNAUTHORIZED_ACCESS");
		expect(err.status).toBe(401);
	});
});

describe("warden > AuthManager factories (AdonisJS parity)", () => {
	it("builds an authenticator for a context", () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});
		const { ctx } = buildCtx({ manager, headers: {} });

		// What the HTTP middleware does per request; anything outside that path
		// had to reach for the class itself.
		expect(manager.createAuthenticator(ctx)).toBeInstanceOf(Authenticator);
	});

	it("refuses to forge a client request for a guard with no test seam", () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: jwtStub },
		});

		// Saying so beats forging headers a guard never agreed to.
		expect(() => manager.createAuthenticatorClient().use("jwt")).toThrow(
			/authenticateAsClient/,
		);
	});
});

describe("warden > a guard is recognised by what it does, not by its name", () => {
	/** The documented config shape: `guards: { web: sessionGuard(...) }`. */
	function namedSessionManager(guardName: string, user: UserPayload | null) {
		const session: AuthStrategy & {
			verifyWithContext(t: string, c: unknown): Promise<AuthResult>;
		} = {
			name: "session",
			async authenticate() {
				return { authenticated: false };
			},
			async verify() {
				return { authenticated: false };
			},
			async verifyWithContext() {
				return user
					? { authenticated: true, user }
					: { authenticated: false, error: "no session user" };
			},
		};
		return new AuthManager({
			default: guardName,
			guards: { [guardName]: session },
		});
	}

	it("authenticates through a guard called `web`", async () => {
		const manager = namedSessionManager("web", okUser);
		const { ctx } = buildCtx({ manager, session: fakeSession() });
		const auth = new Authenticator(ctx, manager);

		await auth.authenticate();

		// Matching the literal name "session" sent this down the bearer-token
		// path, which found no token and refused a perfectly valid session.
		expect(auth.isAuthenticated).toBe(true);
		expect(auth.user?.id).toBe("u1");
		expect(auth.authenticatedViaGuard).toBe("web");
	});

	it("still authenticates through one called `session`", async () => {
		const manager = namedSessionManager("session", okUser);
		const { ctx } = buildCtx({ manager, session: fakeSession() });
		const auth = new Authenticator(ctx, manager);

		await auth.authenticate();

		expect(auth.isAuthenticated).toBe(true);
	});

	it("redirects a browser to the login route for a guard called `web`", async () => {
		class WebCtl {
			@Guard("web")
			async handler() {}
		}
		const manager = namedSessionManager("web", null);
		const { ctx, response } = buildCtx({
			manager,
			controller: WebCtl.prototype,
			action: "handler",
			session: fakeSession(),
			loginRoute: "/login",
			headers: { accept: "text/html" },
		});

		await wardenMiddleware(ctx, async () => {});

		// A browser handed a 401 JSON body instead of the login page is the
		// same bug seen from the other end.
		expect(response.redirectedTo).toBe("/login");
		expect(response.status).toBeUndefined();
	});
});

describe("warden > keep me signed in, end to end", () => {
	/** A host that carries encrypted cookies, like Ream's. */
	function cookieJar() {
		const jar: Record<string, string> = {};
		return {
			jar,
			read: (name: string) => jar[name] ?? null,
			write: (
				name: string,
				value: string,
				options?: Record<string, unknown>,
			) => {
				jar[name] = value;
				jar[`${name}::options`] = JSON.stringify(options ?? {});
			},
			clear: (name: string) => {
				delete jar[name];
			},
		};
	}

	function guardWithTokens(users: Record<string, UserPayload>) {
		const strategy = new SessionStrategy({
			findUser: async (id) => users[String(id)] ?? null,
			rememberMeTokens: new MemoryRememberMeTokenDriver(),
			rememberMeAge: 3600,
		});
		return new AuthManager({ default: "web", guards: { web: strategy } });
	}

	function ctxWith(
		manager: AuthManager,
		cookies: ReturnType<typeof cookieJar>,
		session: SessionStore,
	): WardenContext {
		const bindings = new Map<unknown, unknown>();
		bindings.set(AuthManager, manager);
		return {
			request: { headers: () => ({}), encryptedCookie: cookies.read },
			response: {
				status: () => undefined,
				json: () => undefined,
				encryptedCookie: cookies.write,
				clearCookie: cookies.clear,
			},
			session,
			containerResolver: { make: async (t: unknown) => bindings.get(t) },
		} as unknown as WardenContext;
	}

	it("writes an httpOnly encrypted cookie when the box is ticked", async () => {
		const manager = guardWithTokens({ u1: okUser });
		const cookies = cookieJar();
		const ctx = ctxWith(manager, cookies, fakeSession());

		await new Authenticator(ctx, manager).use("web").login(okUser, true);

		// The cookie IS the credential — anyone who reads it can present it.
		expect(cookies.jar.remember_web).toBeTruthy();
		expect(JSON.parse(cookies.jar["remember_web::options"])).toMatchObject({
			httpOnly: true,
			maxAge: 3600,
		});
	});

	it("clears a standing cookie when the box is NOT ticked", async () => {
		const manager = guardWithTokens({ u1: okUser });
		const cookies = cookieJar();
		cookies.jar.remember_web = "left-over-from-last-time";
		const ctx = ctxWith(manager, cookies, fakeSession());

		await new Authenticator(ctx, manager).use("web").login(okUser);

		// Signing in without ticking has to REVOKE the standing permission.
		expect(cookies.jar.remember_web).toBeUndefined();
	});

	it("revives a returning visitor from the cookie alone", async () => {
		const manager = guardWithTokens({ u1: okUser });
		const cookies = cookieJar();
		await new Authenticator(ctxWith(manager, cookies, fakeSession()), manager)
			.use("web")
			.login(okUser, true);

		// A NEW request: fresh session, same browser.
		const next = new Authenticator(
			ctxWith(manager, cookies, fakeSession()),
			manager,
		);
		await next.authenticate();

		expect(next.isAuthenticated).toBe(true);
		expect(next.user?.id).toBe("u1");
		expect(next.use("web").viaRemember).toBe(true);
	});

	it("recycles the cookie, so a stolen copy stops working", async () => {
		const manager = guardWithTokens({ u1: okUser });
		const cookies = cookieJar();
		await new Authenticator(ctxWith(manager, cookies, fakeSession()), manager)
			.use("web")
			.login(okUser, true);
		const stolen = cookies.jar.remember_web;

		await new Authenticator(
			ctxWith(manager, cookies, fakeSession()),
			manager,
		).authenticate();
		expect(cookies.jar.remember_web).not.toBe(stolen);

		// The thief presents the old value against a fresh session.
		const thief = cookieJar();
		thief.jar.remember_web = stolen;
		const attacker = new Authenticator(
			ctxWith(manager, thief, fakeSession()),
			manager,
		);
		await attacker.authenticate().catch(() => undefined);

		expect(attacker.isAuthenticated).toBe(false);
	});

	it("re-seats the session, so the next request needs no cookie", async () => {
		const manager = guardWithTokens({ u1: okUser });
		const cookies = cookieJar();
		await new Authenticator(ctxWith(manager, cookies, fakeSession()), manager)
			.use("web")
			.login(okUser, true);

		const session = fakeSession();
		await new Authenticator(
			ctxWith(manager, cookies, session),
			manager,
		).authenticate();

		expect(session.get("auth_user_id")).toBe("u1");
	});

	it("says so when the guard has no remember-me configured", async () => {
		const strategy = new SessionStrategy({ findUser: async () => okUser });
		const manager = new AuthManager({
			default: "web",
			guards: { web: strategy },
		});
		const ctx = ctxWith(manager, cookieJar(), fakeSession());

		// Silently ignoring the flag hands the user a box that does nothing.
		await expect(
			new Authenticator(ctx, manager).use("web").login(okUser, true),
		).rejects.toThrow(/cannot keep a user signed in/);
	});
});

describe("warden > a failed sign-in leaves no standing credential", () => {
	it("clears the remember-me cookie when the session write throws", async () => {
		const jar: Record<string, string> = {};
		const strategy = new SessionStrategy({
			findUser: async () => okUser,
			rememberMeTokens: new MemoryRememberMeTokenDriver(),
			rememberMeAge: 3600,
		});
		const manager = new AuthManager({
			default: "web",
			guards: { web: strategy },
		});
		const ctx = {
			request: {
				headers: () => ({}),
				encryptedCookie: (n: string) => jar[n] ?? null,
			},
			response: {
				status: () => undefined,
				json: () => undefined,
				encryptedCookie: (n: string, v: string) => {
					jar[n] = v;
				},
				clearCookie: (n: string) => {
					delete jar[n];
				},
			},
			// A session whose write blows up — a listener, a store, a driver.
			session: {
				get: () => undefined,
				put: () => {
					throw new Error("session store is down");
				},
				forget: () => undefined,
				regenerate: () => undefined,
			},
		} as unknown as WardenContext;

		await expect(
			new Authenticator(ctx, manager).use("web").login(okUser, true),
		).rejects.toThrow(/session store is down/);

		// A sign-in that failed must not leave the browser holding a credential
		// that signs it in on the next request.
		expect(jar.remember_web).toBeUndefined();
	});
});
