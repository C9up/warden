import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { createWarden, type Warden } from "../../src/standalone.js";

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
	req: Record<string, unknown>,
): Promise<{
	captured: ExpressCaptured;
	nextCalled: boolean;
	req: Record<string, unknown>;
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
});

describe("warden > expressMiddleware", () => {
	it("returns 401 when the request has no Bearer token", async () => {
		const warden = buildWarden();
		const out = await runExpress(warden, { headers: {} });

		expect(out.captured.status).toBe(401);
		expect(out.captured.body).toMatchObject({
			error: { code: "UNAUTHORIZED", message: "Missing authentication token" },
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
		expect(out.req.user).toEqual(SAMPLE_USER);
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
			error: { code: "UNAUTHORIZED" },
		});
		expect(out.nextCalled).toBe(false);
	});
});
