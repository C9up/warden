/**
 * The 2026-09-29 audit, one reproduction per finding: Basic auth through the
 * guard loop, single-use remember-me and MFA codes under concurrency, the
 * remember-me cookie's attributes, an MFA step-up the token carries, and the
 * numbers that used to switch a protection off.
 */
import { describe, expect, it, vi } from "vitest";
import {
	type AttemptRedisClient,
	RedisAttemptStore,
} from "../../src/AttemptStore.js";
import { Authenticator } from "../../src/Authenticator.js";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import { E_UNAUTHORIZED_ACCESS } from "../../src/errors.js";
import { BackupCodesProvider } from "../../src/mfa/BackupCodesProvider.js";
import { MfaManager } from "../../src/mfa/MfaManager.js";
import {
	RedisTotpReplayGuard,
	type ReplayRedisClient,
	TotpProvider,
} from "../../src/mfa/TotpProvider.js";
import { renderAuthError, type WardenContext } from "../../src/middleware.js";
import {
	MemoryRememberMeTokenDriver,
	mintRememberMeToken,
	verifyAndRecycleRememberMeToken,
} from "../../src/RememberMeToken.js";
import { BasicAuthStrategy } from "../../src/strategies/BasicAuthStrategy.js";
import { JwtStrategy } from "../../src/strategies/JwtStrategy.js";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";

const USER: UserPayload = { id: "u1" };

function session(): SessionStore {
	const store = new Map<string, unknown>();
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

interface Captured {
	status?: number;
	headers: Record<string, string>;
	cookies: Record<string, Record<string, unknown>>;
}

function context(
	manager: AuthManager,
	options: { headers?: Record<string, string>; session?: SessionStore } = {},
): { ctx: WardenContext; captured: Captured } {
	const captured: Captured = { headers: {}, cookies: {} };
	const ctx: WardenContext = {
		request: { headers: () => options.headers ?? {} },
		response: {
			status(code) {
				captured.status = code;
			},
			json() {},
			header(name, value) {
				captured.headers[name] = value;
			},
			encryptedCookie(name, _value, cookieOptions) {
				captured.cookies[name] = cookieOptions ?? {};
			},
			clearCookie() {},
		},
		session: options.session,
		containerResolver: {
			async make(token) {
				if (token === AuthManager) return manager;
				throw new Error(`No binding for ${String(token)}`);
			},
		},
	};
	return { ctx, captured };
}

describe("warden > Basic auth through the guard loop (034)", () => {
	const basic = () =>
		new BasicAuthStrategy({
			realm: "Admin",
			verifyCredentials: async (uid, password) =>
				uid === "ada" && password === "secret" ? { id: "ada" } : null,
		});
	const header = (uid: string, password: string) =>
		`Basic ${Buffer.from(`${uid}:${password}`).toString("base64")}`;

	it("authenticates a request carrying an Authorization: Basic header", async () => {
		const manager = new AuthManager({
			default: "basic",
			guards: { basic: basic() },
		});
		const { ctx } = context(manager, {
			headers: { authorization: header("ada", "secret") },
		});
		const auth = new Authenticator(ctx, manager);
		await auth.authenticate();
		expect(auth.user?.id).toBe("ada");
	});

	it("answers a refusal with the WWW-Authenticate challenge", async () => {
		const manager = new AuthManager({
			default: "basic",
			guards: { basic: basic() },
		});
		const { ctx, captured } = context(manager, {
			headers: { authorization: header("ada", "wrong") },
		});
		const failure = await new Authenticator(ctx, manager)
			.authenticate()
			.catch((error: unknown) => error);
		expect(failure).toBeInstanceOf(E_UNAUTHORIZED_ACCESS);
		if (!(failure instanceof E_UNAUTHORIZED_ACCESS)) return;
		renderAuthError(ctx, failure);
		expect(captured.status).toBe(401);
		expect(captured.headers["WWW-Authenticate"]).toBe(
			'Basic realm="Admin", charset="UTF-8"',
		);
	});
});

describe("warden > a remember-me token is single-use (035)", () => {
	it("lets exactly one of two concurrent requests with the same cookie through", async () => {
		const driver = new MemoryRememberMeTokenDriver();
		const minted = mintRememberMeToken("u1", 3600);
		await driver.create(minted.stored);
		const results = await Promise.all([
			verifyAndRecycleRememberMeToken(driver, minted.value, 3600),
			verifyAndRecycleRememberMeToken(driver, minted.value, 3600),
		]);
		expect(results.filter((result) => result !== null)).toHaveLength(1);
	});
});

describe("warden > the remember-me cookie's attributes (036)", () => {
	function manager(rememberMeCookie?: { sameSite?: "strict" }) {
		return new AuthManager({
			default: "web",
			guards: {
				web: new SessionStrategy({
					findUser: async () => USER,
					rememberMeTokens: new MemoryRememberMeTokenDriver(),
					rememberMeAge: 3600,
					rememberMeCookie,
				}),
			},
		});
	}

	it("is Secure in production, SameSite=Lax and site-wide", async () => {
		vi.stubEnv("NODE_ENV", "production");
		try {
			const m = manager();
			const { ctx, captured } = context(m, { session: session() });
			await new Authenticator(ctx, m).use("web").login(USER, true);
			expect(captured.cookies.remember_web).toMatchObject({
				httpOnly: true,
				secure: true,
				sameSite: "lax",
				path: "/",
				maxAge: 3600,
			});
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("takes the app's overrides, but never drops httpOnly", async () => {
		const m = manager({ sameSite: "strict" });
		const { ctx, captured } = context(m, { session: session() });
		await new Authenticator(ctx, m).use("web").login(USER, true);
		expect(captured.cookies.remember_web).toMatchObject({
			sameSite: "strict",
			httpOnly: true,
		});
	});
});

describe("warden > a remember-me age must be a number (037)", () => {
	it("refuses NaN, and a stored NaN expiry counts as expired", async () => {
		expect(
			() =>
				new SessionStrategy({
					findUser: async () => USER,
					rememberMeAge: Number.NaN,
				}),
		).toThrow(/rememberMeAge must be a positive whole number/);

		const driver = new MemoryRememberMeTokenDriver();
		const minted = mintRememberMeToken("u1", Number.NaN);
		await driver.create(minted.stored);
		expect(
			await verifyAndRecycleRememberMeToken(driver, minted.value, 3600),
		).toBeNull();
	});
});

describe("warden > the MFA step-up is the credential's (038)", () => {
	const jwt = (findUser: () => Promise<UserPayload>) =>
		new JwtStrategy({
			secret: "a-secret-long-enough-for-hs256-signing",
			verifyCredentials: async () => USER,
			findUser,
		});

	it("reads a signed step-up claim, and only that", async () => {
		// The account has MFA ENABLED: that is not a step-up.
		const strategy = jwt(async () => ({ id: "u1", mfa: true }));
		const plain = await strategy.verify(strategy.signToken(USER));
		expect(plain.user?.mfa).toBe(false);
		const stepped = await strategy.verify(
			strategy.signToken(USER, { mfa: true }),
		);
		expect(stepped.user?.mfa).toBe(true);
	});

	it("issues the step-up through AuthManager.issueFor", async () => {
		const strategy = jwt(async () => USER);
		const manager = new AuthManager({
			default: "jwt",
			guards: { jwt: strategy },
		});
		const token = manager.issueFor(USER, "jwt", { mfa: true });
		expect((await strategy.verify(token)).user?.mfa).toBe(true);
	});

	it("records a session's step-up, and forgets it at the next sign-in", async () => {
		const strategy = new SessionStrategy({ findUser: async () => USER });
		const manager = new AuthManager({
			default: "web",
			guards: { web: strategy },
		});
		const store = session();
		const { ctx } = context(manager, { session: store });
		const guard = new Authenticator(ctx, manager).use("web");
		await guard.login(USER);
		expect(
			(await strategy.verifyWithContext("", { session: store })).user?.mfa,
		).toBe(false);
		guard.markMfaVerified();
		expect(
			(await strategy.verifyWithContext("", { session: store })).user?.mfa,
		).toBe(true);
		await guard.login(USER);
		expect(
			(await strategy.verifyWithContext("", { session: store })).user?.mfa,
		).toBe(false);
	});
});

describe("warden > MFA codes are single-use under concurrency (039)", () => {
	it("accepts a TOTP code once when two requests present it together", async () => {
		const totp = new TotpProvider();
		const { secret } = totp.enroll("a", "b");
		const code = totp.generate(secret);
		const results = await Promise.all([
			totp.verify(secret, code),
			totp.verify(secret, code),
		]);
		expect(results.filter(Boolean)).toHaveLength(1);
	});

	it("accepts a backup code once when two requests present it together", async () => {
		const manager = new MfaManager({
			issuer: "Acme",
			backupCodes: new BackupCodesProvider({ count: 3 }),
		});
		const [code] = await manager.createBackupCodes("u1");
		if (code === undefined) throw new Error("no code");
		const results = await Promise.all([
			manager.verifyBackupCode("u1", code),
			manager.verifyBackupCode("u1", code),
		]);
		expect(results.filter(Boolean)).toHaveLength(1);
	});
});

describe("warden > the MFA lockout holds against a burst (040)", () => {
	it("lets one attempt reach the provider when maxAttempts is 1", async () => {
		const totp = new TotpProvider();
		const verify = vi.spyOn(totp, "verify");
		const manager = new MfaManager({
			issuer: "Acme",
			totp,
			rateLimit: { maxAttempts: 1 },
		});
		const { factorId, secret } = await manager.enrollTotp({
			id: "u1",
			name: "u1",
		});
		await manager.confirmTotp(factorId, totp.generate(secret));
		verify.mockClear();
		await Promise.all(
			Array.from({ length: 20 }, () => manager.verify("u1", "000000")),
		);
		expect(verify).toHaveBeenCalledTimes(1);
		expect(await manager.isLocked("u1")).toBe(true);
	});
});

describe("warden > numbers that switched a protection off (042, 043)", () => {
	it("refuses TOTP periods, windows and digits that break verification", () => {
		for (const config of [
			{ period: 0 },
			{ window: Number.POSITIVE_INFINITY },
			{ digits: Number.NaN },
			{ period: 1.5 },
		]) {
			expect(() => new TotpProvider(config)).toThrow(/must be a whole number/);
		}
	});

	it("refuses backup-code counts and lengths that are not whole numbers", () => {
		expect(() => new BackupCodesProvider({ count: Number.NaN })).toThrow();
		expect(() => new BackupCodesProvider({ length: 8.5 })).toThrow();
	});

	it("refuses a token lifetime of a fraction of a second", () => {
		expect(
			() =>
				new JwtStrategy({
					secret: "a-secret-long-enough-for-hs256-signing",
					verifyCredentials: async () => USER,
					findUser: async () => USER,
					expiresIn: "500ms",
				}),
		).toThrow(/whole number of seconds/);
	});
});

describe("warden > shared stores for a cluster", () => {
	function fakeRedis(): AttemptRedisClient & ReplayRedisClient {
		const values = new Map<string, string>();
		const ttls = new Map<string, number>();
		return {
			async incr(key) {
				const next = Number(values.get(key) ?? "0") + 1;
				values.set(key, String(next));
				return next;
			},
			async expire(key, seconds) {
				ttls.set(key, seconds);
			},
			async ttl(key) {
				return ttls.get(key) ?? -1;
			},
			async get(key) {
				return values.get(key) ?? null;
			},
			async del(key) {
				values.delete(key);
				ttls.delete(key);
			},
			async set(key, value) {
				if (values.has(key)) return null;
				values.set(key, value);
				return "OK";
			},
		};
	}

	it("counts attempts in Redis, with the window set on the first", async () => {
		const redis = fakeRedis();
		const store = new RedisAttemptStore(redis);
		expect(await store.increment("mfa:u1", 900)).toEqual({
			count: 1,
			resetSeconds: 900,
		});
		expect((await store.increment("mfa:u1", 900)).count).toBe(2);
		expect(await store.count("mfa:u1")).toBe(2);
		await store.reset("mfa:u1");
		expect(await store.count("mfa:u1")).toBe(0);
	});

	it("claims a TOTP code once across instances", async () => {
		const guard = new RedisTotpReplayGuard(fakeRedis());
		const one = new TotpProvider({ replayGuard: guard });
		const two = new TotpProvider({ replayGuard: guard });
		const { secret } = one.enroll("a", "b");
		const code = one.generate(secret);
		expect(await one.verify(secret, code)).toBe(true);
		expect(await two.verify(secret, code)).toBe(false);
	});
});
