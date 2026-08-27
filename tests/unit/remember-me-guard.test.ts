/**
 * Remember-me on the session guard: minting at login, authenticating from the
 * cookie, recycling, and revocation at logout.
 *
 * Mirrors `@adonisjs/auth`'s session guard, which mints on
 * `login(user, remember)`, re-reads the user through the provider on the
 * remember path, recycles the token, and deletes the row on logout.
 */
import { describe, expect, it } from "vitest";
import {
	decodeTokenValue,
	MemoryRememberMeTokenDriver,
} from "../../src/RememberMeToken.js";
import { SessionStrategy } from "../../src/strategies/SessionStrategy.js";

function guard(options: { userExists?: boolean } = {}) {
	const tokens = new MemoryRememberMeTokenDriver();
	const strategy = new SessionStrategy({
		findUser: async (id) =>
			options.userExists === false ? null : { id: String(id), email: "a@b.c" },
		rememberMeTokens: tokens,
		rememberMeAge: 3600,
	});
	return { strategy, tokens };
}

function session() {
	const store = new Map<string, unknown>();
	return {
		get: (k: string) => store.get(k),
		put: (k: string, v: unknown) => store.set(k, v),
		forget: (k: string) => store.delete(k),
		regenerate: () => {},
	};
}

describe("warden > remember-me on the session guard", () => {
	it("is off unless a token driver is wired", async () => {
		const bare = new SessionStrategy({ findUser: async () => null });

		expect(bare.usesRememberMeTokens).toBe(false);
		// Nothing to mint, and nothing blows up.
		expect(await bare.issueRememberMeToken({ id: "1" })).toBeNull();
		expect(await bare.authenticateViaRememberMeToken("anything")).toBeNull();
	});

	it("names the cookie the way Adonis does", () => {
		const { strategy } = guard();
		expect(strategy.rememberMeCookieName).toBe("remember_web");
	});

	it("authenticates from the cookie and hands back a recycled one", async () => {
		const { strategy } = guard();
		const issued = await strategy.issueRememberMeToken({ id: "42" });

		const result = await strategy.authenticateViaRememberMeToken(issued);

		expect(result?.user.id).toBe("42");
		// The browser must replace its cookie: the old value is now dead.
		expect(result?.cookieValue).not.toBe(issued);
		expect(await strategy.authenticateViaRememberMeToken(issued)).toBeNull();
	});

	it("re-reads the user rather than trusting the token", async () => {
		// A token outlives the row it points at. A deleted or disabled account
		// must not walk back in through a cookie.
		const { strategy: issuing } = guard();
		const issued = await issuing.issueRememberMeToken({ id: "42" });

		const tokens = new MemoryRememberMeTokenDriver();
		const decoded = decodeTokenValue(issued);
		expect(decoded).not.toBeNull();

		const gone = new SessionStrategy({
			findUser: async () => null,
			rememberMeTokens: tokens,
			rememberMeAge: 3600,
		});
		const minted = await gone.issueRememberMeToken({ id: "42" });

		expect(await gone.authenticateViaRememberMeToken(minted)).toBeNull();
	});

	it("revokes the token so a logged-out cookie stops working", async () => {
		const { strategy } = guard();
		const issued = await strategy.issueRememberMeToken({ id: "42" });

		await strategy.logout(session() as never);
		await strategy.revokeRememberMeToken(issued);

		expect(await strategy.authenticateViaRememberMeToken(issued)).toBeNull();
	});

	it("revoking a malformed or unknown cookie is a no-op", async () => {
		const { strategy } = guard();
		await expect(
			strategy.revokeRememberMeToken("not-a-token"),
		).resolves.toBeUndefined();
		await expect(strategy.revokeRememberMeToken(null)).resolves.toBeUndefined();
	});

	it("issues a distinct token per login", async () => {
		const { strategy } = guard();
		const first = await strategy.issueRememberMeToken({ id: "42" });
		const second = await strategy.issueRememberMeToken({ id: "42" });

		// Two devices, two tokens: signing out of one must not sign out the other.
		expect(first).not.toBe(second);
		await strategy.revokeRememberMeToken(first);
		expect(
			await strategy.authenticateViaRememberMeToken(second),
		).not.toBeNull();
	});
});

describe("warden > the guard says HOW the user got here (AdonisJS viaRemember)", () => {
	it("is false for a fresh login", async () => {
		const { strategy } = guard();
		await strategy.login({ id: "1" }, session() as never);

		expect(strategy.viaRemember).toBe(false);
		expect(strategy.attemptedViaRemember).toBe(false);
	});

	it("is true once a user is revived from the cookie", async () => {
		const { strategy } = guard();
		const value = await strategy.issueRememberMeToken({ id: "1" });

		const revived = await strategy.authenticateViaRememberMeToken(value);

		// This is the distinction that lets an app demand the password again
		// before something sensitive. Nothing reported it, so a session
		// restored from a cookie looked exactly like a fresh sign-in.
		expect(revived).not.toBe(null);
		expect(strategy.viaRemember).toBe(true);
		expect(strategy.attemptedViaRemember).toBe(true);
	});

	it("records the attempt even when the cookie is rejected", async () => {
		const { strategy } = guard();

		expect(await strategy.authenticateViaRememberMeToken("garbage")).toBe(null);
		expect(strategy.attemptedViaRemember).toBe(true);
		expect(strategy.viaRemember).toBe(false);
	});

	it("a real login afterwards clears it", async () => {
		const { strategy } = guard();
		const value = await strategy.issueRememberMeToken({ id: "1" });
		await strategy.authenticateViaRememberMeToken(value);
		expect(strategy.viaRemember).toBe(true);

		// A password was typed: a re-auth prompt must not keep firing.
		await strategy.login({ id: "1" }, session() as never);
		expect(strategy.viaRemember).toBe(false);
	});

	it("logout clears both", async () => {
		const { strategy } = guard();
		const value = await strategy.issueRememberMeToken({ id: "1" });
		await strategy.authenticateViaRememberMeToken(value);

		await strategy.logout(session() as never);

		expect(strategy.viaRemember).toBe(false);
		expect(strategy.attemptedViaRemember).toBe(false);
	});

	it("exposes the session and cookie key names", () => {
		const { strategy } = guard();
		expect(strategy.sessionKeyName).toBe("auth_user_id");
		expect(strategy.rememberMeKeyName).toBe("remember_web");
	});
});

describe("warden > isLoggedOut (AdonisJS parity)", () => {
	it("reports that logout() ran on this guard", async () => {
		const { strategy } = guard();
		expect(strategy.isLoggedOut).toBe(false);

		// A handler that logs out and keeps working — clearing a cart, writing
		// an audit line — could not tell the session was already gone.
		await strategy.logout(session() as never);
		expect(strategy.isLoggedOut).toBe(true);
	});

	it("a later login clears it", async () => {
		const { strategy } = guard();
		await strategy.logout(session() as never);

		await strategy.login({ id: "1" }, session() as never);
		expect(strategy.isLoggedOut).toBe(false);
	});
});
