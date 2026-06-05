/**
 * Cross-package smoke test — `@c9up/sigil` is the canonical password-hashing
 * service for `@c9up/warden`'s `SessionStrategy` flow.
 *
 * This test exercises the actual contract documented in
 * `SessionStrategy.ts:33-37`: the strategy explicitly delegates password
 * verification to the caller. The caller hashes/verifies through Sigil and
 * then hands the authenticated user to `SessionStrategy.login`.
 *
 * Skips when Sigil's NAPI binary is not loadable (CI without prebuilt
 * artifacts; the platform-binary CI matrix is the subject of story 40.4).
 *
 * @implements story 40.3
 */
import { Hash } from "@c9up/sigil";
import { describe, expect, it, type TestContext } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";

/** Narrow away null/undefined without a `!` non-null assertion (which lies to the compiler). */
function defined<T>(value: T | null | undefined): T {
	if (value == null) throw new Error("expected a defined value");
	return value;
}

interface TestUser extends UserPayload {
	id: string;
	email: string;
	passwordHash: string;
}

function makeSessionStore(): SessionStore & { regenerateCalls: number } {
	const store = new Map<string, unknown>();
	let regenerateCalls = 0;
	return {
		get: (key) => store.get(key),
		set: (key, value) => {
			store.set(key, value);
		},
		forget: (key) => {
			store.delete(key);
		},
		// Test fake: count invocations so the suite can assert that login
		// rotates the session id (the SessionStrategy.login fix wires this).
		regenerate: () => {
			regenerateCalls++;
		},
		get regenerateCalls() {
			return regenerateCalls;
		},
	};
}

function makeUserTable(): Map<string, TestUser> {
	return new Map<string, TestUser>();
}

// Probe NAPI availability per-driver at module load via top-level await.
// We probe EACH driver independently because a partial-build (argon2 symbol
// present but bcrypt/scrypt absent) would otherwise let the wrong tests run
// and surface as raw errors instead of clean skips.
const drivers = [
	{ name: "argon2", config: { driver: "argon2" } as Record<string, unknown> },
	{
		name: "bcrypt",
		config: { driver: "bcrypt", rounds: 10 } as Record<string, unknown>,
	},
	{ name: "scrypt", config: { driver: "scrypt" } as Record<string, unknown> },
] as const;

const napiAvailable: Record<string, boolean> = {};
for (const { name, config } of drivers) {
	try {
		const probe = new Hash({ default: name, drivers: { [name]: config } });
		await probe.make("probe");
		napiAvailable[name] = true;
	} catch (err) {
		if (err instanceof Error && err.message.includes("SIGIL_NAPI_REQUIRED"))
			napiAvailable[name] = false;
		else throw err;
	}
}

function skipIfNoNapi(ctx: TestContext, driver: string): void {
	if (!napiAvailable[driver])
		ctx.skip(
			`Sigil NAPI binary not loadable for ${driver} — run \`cargo build --release -p sigil-engine-napi\` and copy the artifact to packages/sigil/index.<platform>.node (story 40.4 will automate this).`,
		);
}

describe("warden + sigil > SessionStrategy design boundary", () => {
	it("SessionStrategy.authenticate() throws — caller must use login() after verifying password themselves", async () => {
		const strategy = new SessionStrategy({ findUser: async () => null });
		await expect(
			strategy.authenticate({ email: "a", password: "b" }),
		).rejects.toThrow(
			/SessionStrategy\.authenticate\(\) requires login\(\) instead/,
		);
	});

	it("numeric user ids: login + verifyWithContext round-trip via findUser(string | number)", async () => {
		// SessionStrategyConfig.findUser accepts `string | number`. Cover the
		// number branch explicitly — without this, a future regression that
		// narrows the parameter type would only surface in production.
		const users = new Map<number, UserPayload>([
			[42, { id: "42", email: "numeric@c9up.test" }],
		]);
		const session = makeSessionStore();
		const strategy = new SessionStrategy({
			findUser: async (id: string | number) =>
				users.get(typeof id === "number" ? id : Number(id)) ?? null,
		});
		await strategy.login({ id: 42 } as unknown as UserPayload, session);
		expect(session.get("auth_user_id")).toBe(42);
		// Session-fixation mitigation regression: login() MUST rotate the
		// session id before writing the authenticated user id. Otherwise an
		// attacker who seeded the victim's session cookie pre-login
		// continues to hold a valid post-login session under the same id.
		expect(session.regenerateCalls).toBe(1);
		const result = await strategy.verifyWithContext("unused", { session });
		expect(result.authenticated).toBe(true);
		expect(result.user?.email).toBe("numeric@c9up.test");
	});
});

describe("warden + sigil > bcrypt rounds floor", () => {
	it("Sigil rejects bcrypt rounds below the OWASP floor (10)", async (ctx) => {
		skipIfNoNapi(ctx, "bcrypt");
		// The Rust crate enforces a minimum of 10 (per its OWASP-aligned guard).
		// Asserting this in the smoke suite means a future Rust-side floor change
		// surfaces as a test failure rather than silent behavioural drift.
		const hash = new Hash({
			default: "bcrypt",
			drivers: { bcrypt: { driver: "bcrypt", rounds: 4 } },
		});
		await expect(hash.make("x")).rejects.toThrow(
			/cost.*below.*minimum.*10|OWASP/i,
		);
	});
});

describe.each(drivers)("warden + sigil > $name driver", ({ name, config }) => {
	it("happy path: hash → verify → login → verifyWithContext authenticates", async (ctx) => {
		skipIfNoNapi(ctx, name);
		const hash = new Hash({ default: name, drivers: { [name]: config } });
		const users = makeUserTable();
		const session = makeSessionStore();

		const passwordHash = await hash.make("correct-horse");
		const user: TestUser = { id: "u1", email: "alice@c9up.test", passwordHash };
		users.set(user.id, user);

		const stored = defined(users.get(user.id));
		const verified = await hash.verify("correct-horse", stored.passwordHash);
		expect(verified).toBe(true);

		const strategy = new SessionStrategy({
			findUser: async (id) => users.get(String(id)) ?? null,
		});
		await strategy.login(user, session);

		const result = await strategy.verifyWithContext("unused", { session });
		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe("u1");
		expect(result.user?.email).toBe("alice@c9up.test");
	});

	it("wrong password: hash.verify === false, login is not reached", async (ctx) => {
		skipIfNoNapi(ctx, name);
		const hash = new Hash({ default: name, drivers: { [name]: config } });
		const users = makeUserTable();
		const session = makeSessionStore();

		const passwordHash = await hash.make("correct-horse");
		const user: TestUser = { id: "u2", email: "bob@c9up.test", passwordHash };
		users.set(user.id, user);

		const verified = await hash.verify("battery-staple", user.passwordHash);
		expect(verified).toBe(false);

		expect(session.get("auth_user_id")).toBeUndefined();

		const strategy = new SessionStrategy({
			findUser: async (id) => users.get(String(id)) ?? null,
		});
		const result = await strategy.verifyWithContext("unused", { session });
		expect(result.authenticated).toBe(false);
		expect(result.error).toBe("No session user");
	});

	it("post-login session forget: verifyWithContext returns no-session-user", async (ctx) => {
		skipIfNoNapi(ctx, name);
		const hash = new Hash({ default: name, drivers: { [name]: config } });
		const users = makeUserTable();
		const session = makeSessionStore();

		const passwordHash = await hash.make("correct-horse");
		const user: TestUser = { id: "u3", email: "carol@c9up.test", passwordHash };
		users.set(user.id, user);

		const strategy = new SessionStrategy({
			findUser: async (id) => users.get(String(id)) ?? null,
		});
		await strategy.login(user, session);
		expect(
			(await strategy.verifyWithContext("unused", { session })).authenticated,
		).toBe(true);

		await strategy.logout(session);

		const result = await strategy.verifyWithContext("unused", { session });
		expect(result.authenticated).toBe(false);
		expect(result.error).toBe("No session user");
	});
});
