/**
 * The Twitter OAuth1 flow end to end, with `fetch` stubbed.
 *
 * The shape that matters: the redirect cannot be built offline, the callback
 * verifies the returned request token, and every call is signed.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { socials } from "../../src/config.js";
import { TwitterDriver } from "../../src/firstcontact/drivers/TwitterDriver.js";

const config = {
	clientId: "cid",
	clientSecret: "secret",
	callbackUrl: "https://app.test/cb",
};

type Reply = { ok: boolean; status: number; body: string | unknown };

function stubFetch(...replies: Reply[]) {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	let i = 0;
	vi.stubGlobal("fetch", (url: string, init?: RequestInit) => {
		calls.push({ url, init });
		const reply = replies[i++] ?? { ok: false, status: 500, body: "" };
		return Promise.resolve({
			ok: reply.ok,
			status: reply.status,
			text: async () => String(reply.body),
			json: async () => reply.body,
		});
	});
	return calls;
}

/** The Authorization header of a recorded call. */
function auth(call: { init?: RequestInit }): string {
	return (call.init?.headers as Record<string, string>).Authorization;
}

const requestToken: Reply = {
	ok: true,
	status: 200,
	body: "oauth_token=rt&oauth_token_secret=rts&oauth_callback_confirmed=true",
};
const accessToken: Reply = {
	ok: true,
	status: 200,
	body: "oauth_token=at&oauth_token_secret=ats&user_id=1&screen_name=kaen",
};

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("warden > Twitter (OAuth1) > begin", () => {
	it("asks X for a request token and points at the authorize URL", async () => {
		const calls = stubFetch(requestToken);
		const started = await new TwitterDriver(config).begin();

		expect(calls[0].url).toBe("https://api.twitter.com/oauth/request_token");
		expect(calls[0].init?.method).toBe("POST");
		expect(started.url).toBe(
			"https://api.twitter.com/oauth/authenticate?oauth_token=rt",
		);
		// Both have to survive until the user comes back: the token is what the
		// callback is checked against, the secret signs the exchange.
		expect(started.state).toBe("rt");
		expect(started.secret).toBe("rts");
	});

	it("signs the request-token call with the callback URL", async () => {
		const calls = stubFetch(requestToken);
		await new TwitterDriver(config).begin();

		const header = auth(calls[0]);
		expect(header).toContain('oauth_callback="https%3A%2F%2Fapp.test%2Fcb"');
		expect(header).toContain('oauth_consumer_key="cid"');
		expect(header).toContain("oauth_signature=");
		// No token exists yet, so none may be claimed.
		expect(header).not.toContain("oauth_token=");
	});

	it("says so when X does not confirm the callback URL", async () => {
		stubFetch({
			ok: true,
			status: 200,
			body: "oauth_token=rt&oauth_token_secret=rts&oauth_callback_confirmed=false",
		});
		// X refuses a callback URL the application has not registered; without
		// this the flow would fail three calls later, on something unrelated.
		await expect(new TwitterDriver(config).begin()).rejects.toThrow(
			/did not confirm the callback URL/,
		);
	});

	it("refuses to build a redirect offline", () => {
		// The URL carries a token only X can issue, so there is nothing useful
		// to return here.
		expect(() => new TwitterDriver(config).redirectUrl()).toThrow(
			/begin\(\) instead of redirect\(\)/,
		);
	});
});

describe("warden > Twitter (OAuth1) > callback", () => {
	it("rejects a request token that is not the one it issued", async () => {
		// OAuth1's CSRF check: the token coming back has to be ours.
		await expect(
			new TwitterDriver(config).callback("verifier", "other", "rt", "rts"),
		).rejects.toThrow(/state mismatch/);
	});

	it("refuses to run without the request-token secret", async () => {
		await expect(
			new TwitterDriver(config).callback("verifier", "rt", "rt"),
		).rejects.toThrow(/request-token secret/);
	});

	it("exchanges the verifier and reads the profile", async () => {
		const calls = stubFetch(accessToken, {
			ok: true,
			status: 200,
			body: {
				id_str: "42",
				screen_name: "kaen",
				name: "Kaen K.",
				email: "k@acme.test",
				profile_image_url_https: "https://pbs.test/a_normal.jpg",
			},
		});

		const out = await new TwitterDriver(config).callback(
			"verifier",
			"rt",
			"rt",
			"rts",
		);

		expect(calls[0].url).toBe("https://api.twitter.com/oauth/access_token");
		expect(auth(calls[0])).toContain('oauth_verifier="verifier"');
		expect(auth(calls[0])).toContain('oauth_token="rt"');

		// The address only arrives when it is asked for.
		expect(calls[1].url).toContain("include_email=true");

		expect(out.user.id).toBe("42");
		expect(out.user.nickName).toBe("kaen");
		expect(out.user.email).toBe("k@acme.test");
		// The thumbnail suffix is dropped for the full-size original.
		expect(out.user.avatarUrl).toBe("https://pbs.test/a.jpg");
		// An OAuth1 access token is useless without its secret.
		expect(out.token).toEqual({ accessToken: "at", tokenSecret: "ats" });
	});

	it("keeps the id as a string, which is the only lossless form", async () => {
		stubFetch(accessToken, {
			ok: true,
			status: 200,
			body: {
				id_str: "1234567890123456789",
				id: 1234567890123456789,
				screen_name: "kaen",
				profile_image_url_https: "https://pbs.test/a_normal.jpg",
			},
		});
		const out = await new TwitterDriver(config).callback(
			"v",
			"rt",
			"rt",
			"rts",
		);

		// The numeric form loses precision past 2^53.
		expect(out.user.id).toBe("1234567890123456789");
	});
});

describe("warden > Twitter (OAuth1) > a token already held", () => {
	it("needs the secret as well", async () => {
		await expect(new TwitterDriver(config).userFromToken("at")).rejects.toThrow(
			/token secret/,
		);
	});

	it("reads the profile when both are supplied", async () => {
		const calls = stubFetch({
			ok: true,
			status: 200,
			body: {
				id_str: "42",
				screen_name: "kaen",
				profile_image_url_https: "https://pbs.test/a_normal.jpg",
			},
		});
		const user = await new TwitterDriver(config).userFromToken("at", "ats");

		expect(calls).toHaveLength(1);
		expect(auth(calls[0])).toContain('oauth_token="at"');
		expect(user.nickName).toBe("kaen");
	});
});

describe("warden > socials", () => {
	it("builds the OAuth1 driver for twitter and the OAuth2 one for twitterX", () => {
		expect(socials.twitter(config)()).toBeInstanceOf(TwitterDriver);
		// Same provider, two protocols, two helpers — as upstream names them.
		expect(socials.twitterX(config)()).not.toBeInstanceOf(TwitterDriver);
	});
});
