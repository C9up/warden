/**
 * A logout holds, whatever the browser — or anyone holding a copy — sends next.
 *
 * Under the cookie session driver the session IS the cookie: logout can only
 * replace the one in THIS browser. A request running across the logout
 * re-sent the signed-in cookie after it, and a cookie copied before it stayed
 * signed in until it expired. Upstream's guard has both holes; here every
 * sign-in gets an id, a logout lists it, and a session carrying a listed id is
 * signed out — the same seam `JwtStrategy` has for tokens.
 *
 * A cookie session is modelled by what it carries: a copy of the session data.
 */

import { describe, expect, it } from "vitest";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";
import {
	MemoryBlacklistDriver,
	TokenBlacklist,
} from "../../src/TokenBlacklist.js";

interface CookieSession extends SessionStore {
	readonly data: Map<string, unknown>;
	rotations: number;
}

/** A session seeded from what a cookie carried. */
function fromCookie(
	copy: ReadonlyMap<string, unknown> = new Map(),
): CookieSession {
	const data = new Map(copy);
	return {
		data,
		rotations: 0,
		config: { ttl: 600 },
		get: (key) => data.get(key),
		put: (key, value) => {
			data.set(key, value);
		},
		forget: (key) => {
			data.delete(key);
		},
		regenerate() {
			this.rotations += 1;
		},
	};
}

function guard(blacklist?: TokenBlacklist) {
	return new SessionStrategy({
		findUser: async (id) => ({ id: String(id), email: "a@b.c" }),
		blacklist,
	});
}

async function signedIn(strategy: SessionStrategy, session: SessionStore) {
	return (await strategy.verifyWithContext("", { session })).authenticated;
}

describe("warden > logout under a cookie session", () => {
	it("signs out a cookie copied before the logout", async () => {
		const strategy = guard(new TokenBlacklist(new MemoryBlacklistDriver()));
		const browser = fromCookie();
		await strategy.login({ id: "7", email: "a@b.c" }, browser);
		const copied = new Map(browser.data);

		await strategy.logout(fromCookie(copied));

		const replay = fromCookie(copied);
		expect(await signedIn(strategy, replay)).toBe(false);
		// Forgotten, so the cookie the server sends back carries nothing to
		// outlive the listing with.
		expect(replay.get("auth_user_id")).toBeUndefined();
		expect(replay.get("auth_user_id_sid")).toBeUndefined();
	});

	it("signs out the cookie a request running across the logout re-sent", async () => {
		const strategy = guard(new TokenBlacklist(new MemoryBlacklistDriver()));
		const browser = fromCookie();
		await strategy.login({ id: "7", email: "a@b.c" }, browser);
		// Read on the way in, re-emitted on the way out: what a rolling cookie does.
		const inFlight = new Map(browser.data);

		await strategy.logout(fromCookie(browser.data));

		expect(await signedIn(strategy, fromCookie(inFlight))).toBe(false);
	});

	it("leaves another sign-in of the same user alone", async () => {
		const strategy = guard(new TokenBlacklist(new MemoryBlacklistDriver()));
		const laptop = fromCookie();
		const phone = fromCookie();
		await strategy.login({ id: "7", email: "a@b.c" }, laptop);
		await strategy.login({ id: "7", email: "a@b.c" }, phone);

		await strategy.logout(fromCookie(laptop.data));

		expect(await signedIn(strategy, phone)).toBe(true);
	});

	it("refuses a session with no sign-in id once a blacklist is set", async () => {
		// One it could never revoke — as JwtStrategy refuses a token with no jti.
		const strategy = guard(new TokenBlacklist(new MemoryBlacklistDriver()));
		const old = fromCookie(new Map([["auth_user_id", "7"]]));
		expect(await signedIn(strategy, old)).toBe(false);
	});

	it("lists the sign-in for twice the session's lifetime", async () => {
		const added: number[] = [];
		const driver = new MemoryBlacklistDriver();
		const strategy = guard(
			new TokenBlacklist({
				add: async (jti, expiresAt) => {
					added.push(expiresAt);
					await driver.add(jti, expiresAt);
				},
				has: (jti) => driver.has(jti),
			}),
		);
		const browser = fromCookie();
		await strategy.login({ id: "7", email: "a@b.c" }, browser);

		const before = Date.now();
		await strategy.logout(fromCookie(browser.data));

		const expiresAt = added[0] ?? 0;
		expect(expiresAt).toBeGreaterThanOrEqual(before + 1_200_000);
		expect(expiresAt).toBeLessThan(before + 1_200_000 + 5_000);
	});
});

describe("warden > a store that cannot revoke", () => {
	function cookieStore(): CookieSession {
		return { ...fromCookie(), revocable: false };
	}

	it("refuses to sign in without a blacklist", async () => {
		// Signed in there, the user could never be signed out for good. The
		// app finds out at its first login, not after a stolen cookie.
		await expect(
			guard().login({ id: "7", email: "a@b.c" }, cookieStore()),
		).rejects.toThrow(/cannot revoke a sign-in/);
	});

	it("signs in once a blacklist is set", async () => {
		const session = cookieStore();
		await guard(new TokenBlacklist(new MemoryBlacklistDriver())).login(
			{ id: "7", email: "a@b.c" },
			session,
		);
		expect(session.get("auth_user_id")).toBe("7");
	});

	it("leaves a server-side store alone", async () => {
		const session = { ...fromCookie(), revocable: true };
		await guard().login({ id: "7", email: "a@b.c" }, session);
		expect(session.get("auth_user_id")).toBe("7");
	});
});

describe("warden > logout rotates the session id", () => {
	it("rotates it, so a request still in flight has no entry to write back to", async () => {
		const strategy = guard();
		const browser = fromCookie();
		await strategy.login({ id: "7", email: "a@b.c" }, browser);
		const rotationsAtLogin = browser.rotations;

		await strategy.logout(browser);

		expect(browser.rotations).toBe(rotationsAtLogin + 1);
		expect(await signedIn(strategy, browser)).toBe(false);
	});

	it("refuses a sessionAge that is not a positive whole number", () => {
		expect(
			() =>
				new SessionStrategy({
					findUser: async () => null,
					sessionAge: Number.NaN,
				}),
		).toThrow(/sessionAge/);
	});
});
