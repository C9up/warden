/**
 * Unit coverage for `SessionStrategy`'s password-delegation contract.
 *
 * `SessionStrategy` (SessionStrategy.ts:33-37) does NOT verify passwords
 * itself — it delegates verification to the caller and only accepts an
 * already-authenticated user via `login()`. This suite exercises that
 * contract with a trivial in-test hasher, so warden stays testable in
 * isolation with zero cross-package dependencies. The real-world pairing
 * with a hashing service (e.g. `@c9up/sigil`) is an application concern and
 * belongs in the kitchen-sink integration app, not in warden's own suite.
 */
import { describe, expect, it } from "vitest";
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

/**
 * Trivial in-test hasher. `SessionStrategy` never calls it — it stands in for
 * whatever hashing service the application wires up, proving the strategy is
 * hasher-agnostic.
 */
const hasher = {
	make: async (plain: string) => `hashed:${plain}`,
	verify: async (plain: string, hash: string) => hash === `hashed:${plain}`,
};

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

describe("SessionStrategy > design boundary", () => {
	it("authenticate() throws — caller must use login() after verifying the password themselves", async () => {
		const strategy = new SessionStrategy({ findUser: async () => null });
		await expect(
			strategy.authenticate({ email: "a", password: "b" }),
		).rejects.toThrow(
			/SessionStrategy\.authenticate\(\) requires login\(\) instead/,
		);
	});
});

describe("SessionStrategy > caller-verified password flow", () => {
	it("happy path: caller verifies hash → login → verifyWithContext authenticates", async () => {
		const users = makeUserTable();
		const session = makeSessionStore();

		const passwordHash = await hasher.make("correct-horse");
		const user: TestUser = { id: "u1", email: "alice@c9up.test", passwordHash };
		users.set(user.id, user);

		const stored = defined(users.get(user.id));
		expect(await hasher.verify("correct-horse", stored.passwordHash)).toBe(true);

		const strategy = new SessionStrategy({
			findUser: async (id) => users.get(String(id)) ?? null,
		});
		await strategy.login(user, session);

		// Session-fixation mitigation regression: login() MUST rotate the
		// session id before writing the authenticated user id. Otherwise an
		// attacker who seeded the victim's session cookie pre-login continues
		// to hold a valid post-login session under the same id.
		expect(session.regenerateCalls).toBe(1);

		const result = await strategy.verifyWithContext("unused", { session });
		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe("u1");
		expect(result.user?.email).toBe("alice@c9up.test");
	});

	it("wrong password: caller's verify is false, no session is created", async () => {
		const users = makeUserTable();
		const session = makeSessionStore();

		const passwordHash = await hasher.make("correct-horse");
		const user: TestUser = { id: "u2", email: "bob@c9up.test", passwordHash };
		users.set(user.id, user);

		expect(await hasher.verify("battery-staple", user.passwordHash)).toBe(
			false,
		);
		expect(session.get("auth_user_id")).toBeUndefined();

		const strategy = new SessionStrategy({
			findUser: async (id) => users.get(String(id)) ?? null,
		});
		const result = await strategy.verifyWithContext("unused", { session });
		expect(result.authenticated).toBe(false);
		expect(result.error).toBe("No session user");
	});

	it("post-login logout: verifyWithContext returns no-session-user", async () => {
		const users = makeUserTable();
		const session = makeSessionStore();

		const passwordHash = await hasher.make("correct-horse");
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
