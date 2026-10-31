/**
 * A logout holds against a request that outlasts the revocation window.
 *
 * A sign-in is listed for twice the session's lifetime. A rolling cookie
 * session used to re-issue its data with a full lifetime counted from the
 * RESPONSE: a request read before the logout and answered after the listing
 * expired handed the browser a fresh cookie whose sign-in nothing refused any
 * more. Ream now counts that lifetime from when the request read the session,
 * so no cookie carrying the sign-in outlives the logout by more than one
 * lifetime — inside the window the listing covers.
 *
 * Ream's real session middleware, under the cookie driver, with this guard.
 */

import { Session, SessionMiddleware } from "@c9up/ream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionStrategy } from "../../src/strategies/SessionStrategy.js";
import {
	MemoryBlacklistDriver,
	TokenBlacklist,
} from "../../src/TokenBlacklist.js";

const SECRET = "a-secret-long-enough-for-the-cookie-driver";

interface FakeCtx {
	request: {
		header(name: string): string | undefined;
		cookie(name: string): string | null;
		plainCookie(name: string): string | null;
		original(): Record<string, unknown>;
	};
	response: {
		cookies: string[];
		cookie(name: string, value: string): void;
		plainCookie(name: string, value: string): void;
	};
	store: Map<string, unknown>;
}

function makeCtx(cookie?: string): FakeCtx {
	return {
		request: {
			header: () => undefined,
			cookie: () => cookie ?? null,
			plainCookie: () => cookie ?? null,
			original: () => ({}),
		},
		response: {
			cookies: [],
			cookie(_name, value) {
				this.cookies.push(value);
			},
			plainCookie(_name, value) {
				this.cookies.push(value);
			},
		},
		store: new Map(),
	};
}

function sessionOf(ctx: FakeCtx): Session {
	const session = ctx.store.get("session");
	if (!(session instanceof Session)) throw new Error("no session");
	return session;
}

afterEach(() => {
	vi.useRealTimers();
});

describe("warden > a request longer than the revocation window", () => {
	it("cannot sign the browser back in", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-10-30T08:00:00Z"));
		const mw = new SessionMiddleware({
			driver: "cookie",
			secret: SECRET,
			maxAge: 600,
			rolling: true,
		});
		const strategy = new SessionStrategy({
			findUser: async (id) => ({ id: String(id), email: "a@b.c" }),
			blacklist: new TokenBlacklist(new MemoryBlacklistDriver()),
		});
		const run = async (ctx: FakeCtx, work: (s: Session) => Promise<void>) =>
			mw.handle(ctx as never, () => work(sessionOf(ctx)));
		const signedIn = async (cookie: string) => {
			let authenticated = false;
			await run(makeCtx(cookie), async (session) => {
				authenticated = (await strategy.verifyWithContext("", { session }))
					.authenticated;
			});
			return authenticated;
		};

		const login = makeCtx();
		await run(login, (session) =>
			strategy.login({ id: "7", email: "a@b.c" }, session),
		);
		const signedInCookie = login.response.cookies.at(-1) ?? "";
		expect(await signedIn(signedInCookie)).toBe(true);

		let release = (): void => {};
		const slow = makeCtx(signedInCookie);
		const slowDone = run(slow, async (session) => {
			await new Promise<void>((resolve) => {
				release = resolve;
			});
			session.put("throttle", 1);
		});

		const out = makeCtx(signedInCookie);
		await run(out, (session) => strategy.logout(session));
		const signedOutCookie = out.response.cookies.at(-1) ?? "";

		// The listing is kept until 08:20; the slow request answers at 08:21.
		vi.setSystemTime(new Date("2026-10-30T08:21:00Z"));
		release();
		await slowDone;

		const browserCookie = slow.response.cookies.at(-1) ?? signedOutCookie;
		expect(await signedIn(browserCookie)).toBe(false);
		expect(await signedIn(signedInCookie)).toBe(false);
	});
});
