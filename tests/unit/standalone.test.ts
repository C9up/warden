import { describe, expect, it, vi } from "vitest";
import {
	AccessTokensProvider,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import type { UserPayload } from "../../src/AuthManager.js";
import { jwtGuard, sessionGuard } from "../../src/config.js";
import {
	createWarden,
	type StandaloneRequest,
	type Warden,
} from "../../src/standalone.js";

const SECRET = "x".repeat(32);

const SAMPLE_USER: UserPayload = {
	id: "u-42",
	roles: ["admin"],
	permissions: ["o.read"],
};

function buildWarden(): Warden {
	return createWarden({
		defaultStrategy: "jwt",
		jwt: {
			secret: SECRET,
			expiresInSeconds: 60,
			async findUser(id) {
				return id === SAMPLE_USER.id ? SAMPLE_USER : null;
			},
			async verifyCredentials(email, password) {
				return email === "ok@x" && password === "p" ? SAMPLE_USER : null;
			},
		},
	});
}

interface ExpressCaptured {
	status?: number;
	body?: unknown;
}

function makeRes(): {
	res: { status: (n: number) => { json: (d: unknown) => void } };
	captured: ExpressCaptured;
} {
	const captured: ExpressCaptured = {};
	return {
		captured,
		res: {
			status(code) {
				captured.status = code;
				return {
					json(data) {
						captured.body = data;
					},
				};
			},
		},
	};
}

function runExpress(
	warden: Warden,
	req: StandaloneRequest,
): Promise<{
	captured: ExpressCaptured;
	nextCalled: boolean;
	req: StandaloneRequest;
}> {
	const mw = warden.expressMiddleware();
	const { res, captured } = makeRes();
	return new Promise((resolve) => {
		let nextCalled = false;
		mw(req, res, () => {
			nextCalled = true;
		});
		// Drain microtasks twice — verify().then() chains a then on a promise.
		queueMicrotask(() =>
			queueMicrotask(() =>
				queueMicrotask(() => resolve({ captured, nextCalled, req })),
			),
		);
	});
}

describe("warden > createWarden", () => {
	it("constructs a manager wired with the JWT strategy from config", () => {
		const warden = buildWarden();
		expect(() => warden.manager.getStrategy("jwt")).not.toThrow();
	});

	it("falls back to defaultStrategy='jwt' when omitted", () => {
		const warden = createWarden({
			jwt: {
				secret: SECRET,
				async findUser() {
					return null;
				},
				async verifyCredentials() {
					return null;
				},
			},
		});
		expect(() => warden.manager.getStrategy("jwt")).not.toThrow();
	});

	it("authenticate() round-trips through the configured verifyCredentials", async () => {
		const warden = buildWarden();
		const ok = await warden.authenticate({ email: "ok@x", password: "p" });
		expect(ok.authenticated).toBe(true);
		expect(ok.user?.id).toBe(SAMPLE_USER.id);

		const ko = await warden.authenticate({ email: "wrong", password: "wrong" });
		expect(ko.authenticated).toBe(false);
	});

	it("generateToken() produces a token verify() then accepts", async () => {
		const warden = buildWarden();
		const token = await warden.generateToken(SAMPLE_USER);
		expect(typeof token).toBe("string");
		const result = await warden.verify(token);
		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe(SAMPLE_USER.id);
	});

	it("verify() rejects malformed tokens with an unauthenticated result", async () => {
		const warden = buildWarden();
		const result = await warden.verify("not-a-real-jwt");
		expect(result.authenticated).toBe(false);
	});

	it("wires the api-key strategy from config.apiKey (jwt-less config doesn't throw)", async () => {
		// Before the fix only config.jwt was wired, so this jwt-less config threw
		// AuthManager INVALID_CONFIG at construction (audit 2026-06-13).
		const tokens = new AccessTokensProvider({
			store: new MemoryAccessTokenStore(),
		});
		const warden = createWarden({
			defaultStrategy: "api-key",
			apiKey: {
				tokens,
				async findUser(id) {
					return id === "u1" ? { id: "u1" } : null;
				},
			},
		});
		const minted = await tokens.create({ id: "u1" }, ["orders.read"]);
		const value = minted.value?.release() ?? "";
		const ok = await warden.verify(value, "api-key");
		expect(ok.authenticated).toBe(true);
		expect(ok.user?.id).toBe("u1");
		const bad = await warden.verify("wrong", "api-key");
		expect(bad.authenticated).toBe(false);
	});
});

describe("warden > expressMiddleware", () => {
	it("returns 401 when the request has no Bearer token", async () => {
		const warden = buildWarden();
		const out = await runExpress(warden, { headers: {} });

		expect(out.captured.status).toBe(401);
		expect(out.captured.body).toMatchObject({
			error: {
				code: "E_WARDEN_UNAUTHORIZED",
				message: "Missing authentication token",
			},
		});
		expect(out.nextCalled).toBe(false);
	});

	it("returns 401 when the Authorization scheme is not 'Bearer'", async () => {
		const warden = buildWarden();
		const out = await runExpress(warden, {
			headers: { authorization: "Basic dXNlcjpwYXNz" },
		});
		expect(out.captured.status).toBe(401);
		expect(out.nextCalled).toBe(false);
	});

	it("attaches req.auth + req.user on a valid token then calls next()", async () => {
		const warden = buildWarden();
		const token = await warden.generateToken(SAMPLE_USER);
		const out = await runExpress(warden, {
			headers: { authorization: `Bearer ${token}` },
		});

		expect(out.captured.status).toBeUndefined();
		expect(out.nextCalled).toBe(true);
		expect(out.req.auth).toMatchObject({ authenticated: true });
		// `mfa` is the token's step-up claim: this one never stepped up.
		expect(out.req.user).toEqual({ ...SAMPLE_USER, mfa: false });
	});

	it("accepts a lower-case bearer scheme", async () => {
		const warden = buildWarden();
		const token = await warden.generateToken(SAMPLE_USER);
		const out = await runExpress(warden, {
			headers: { authorization: `bearer ${token}` },
		});

		expect(out.captured.status).toBeUndefined();
		expect(out.nextCalled).toBe(true);
	});

	it("returns 401 on a malformed Bearer token", async () => {
		const warden = buildWarden();
		const out = await runExpress(warden, {
			headers: { authorization: "Bearer not-a-jwt" },
		});
		expect(out.captured.status).toBe(401);
		expect(out.nextCalled).toBe(false);
	});

	it("returns 401 on a token whose user is no longer found", async () => {
		// findUser returns null → AuthManager.verify resolves false.
		const warden = createWarden({
			defaultStrategy: "jwt",
			jwt: {
				secret: SECRET,
				async findUser() {
					return null;
				},
				async verifyCredentials() {
					return null;
				},
			},
		});
		// We need a syntactically valid token signed with the same secret.
		const otherWarden = buildWarden();
		const token = await otherWarden.generateToken(SAMPLE_USER);

		const out = await runExpress(warden, {
			headers: { authorization: `Bearer ${token}` },
		});
		expect(out.captured.status).toBe(401);
		expect(out.captured.body).toMatchObject({
			error: { code: "E_WARDEN_UNAUTHORIZED" },
		});
		expect(out.nextCalled).toBe(false);
	});
});

describe("warden > expressMiddleware — a crashed guard is a server error", () => {
	function crashingWarden(): Warden {
		return createWarden({
			defaultStrategy: "jwt",
			jwt: {
				secret: SECRET,
				async findUser() {
					throw new Error("connect ECONNREFUSED 10.0.0.5:5432");
				},
				async verifyCredentials() {
					return null;
				},
			},
		});
	}

	it("answers 500 with a generic message, never the thrown one", async () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			const token = await buildWarden().generateToken(SAMPLE_USER);
			const out = await runExpress(crashingWarden(), {
				headers: { authorization: `Bearer ${token}` },
			});

			expect(out.captured.status).toBe(500);
			expect(out.captured.body).toEqual({
				error: {
					code: "E_WARDEN_AUTH_STRATEGY_ERROR",
					message: "Authentication unavailable. Check server logs.",
				},
			});
			expect(JSON.stringify(out.captured.body)).not.toContain("ECONNREFUSED");
			expect(out.nextCalled).toBe(false);
			// The cause still reaches the operator.
			expect(String(error.mock.calls[0]?.[0])).toContain("ECONNREFUSED");
		} finally {
			error.mockRestore();
		}
	});
});

describe("warden > generateToken picks the configured guard", () => {
	const jwtConfig = {
		secret: SECRET,
		async findUser(id: string) {
			return id === SAMPLE_USER.id ? SAMPLE_USER : null;
		},
		async verifyCredentials() {
			return null;
		},
	};

	it("mints through the default guard, whatever it is called", async () => {
		const warden = createWarden({
			default: "api",
			guards: { api: jwtGuard(jwtConfig) },
		});

		const token = await warden.generateToken(SAMPLE_USER);

		expect((await warden.verify(token)).user?.id).toBe(SAMPLE_USER.id);
	});

	it("mints through a named guard", async () => {
		const warden = createWarden({
			default: "web",
			guards: {
				web: sessionGuard({ findUser: async () => null }),
				api: jwtGuard(jwtConfig),
			},
		});

		const token = await warden.generateToken(SAMPLE_USER, "api");

		expect((await warden.verify(token, "api")).authenticated).toBe(true);
	});

	it("says so when the guard mints no tokens", async () => {
		const warden = createWarden({
			default: "web",
			guards: { web: sessionGuard({ findUser: async () => null }) },
		});

		await expect(warden.generateToken(SAMPLE_USER)).rejects.toThrow(
			/cannot issue tokens/,
		);
	});
});
