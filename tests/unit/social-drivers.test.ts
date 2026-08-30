/**
 * The OAuth2 drivers behind `socials.*`.
 *
 * Each provider differs in three places — where the user is sent, how the
 * client authenticates on the token request, and what its profile payload is
 * called. These cover exactly that, plus the PKCE requirement X enforces.
 */
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { socials } from "../../src/config.js";
import { DiscordDriver } from "../../src/firstcontact/drivers/DiscordDriver.js";
import { FacebookDriver } from "../../src/firstcontact/drivers/FacebookDriver.js";
import { GitHubDriver } from "../../src/firstcontact/drivers/GitHubDriver.js";
import { GoogleDriver } from "../../src/firstcontact/drivers/GoogleDriver.js";
import { LinkedInDriver } from "../../src/firstcontact/drivers/LinkedInDriver.js";
import { LinkedInOpenidConnectDriver } from "../../src/firstcontact/drivers/LinkedInOpenidConnectDriver.js";
import { SpotifyDriver } from "../../src/firstcontact/drivers/SpotifyDriver.js";
import { TwitterDriver } from "../../src/firstcontact/drivers/TwitterDriver.js";
import { createCodeVerifier } from "../../src/firstcontact/Oauth2Driver.js";
import type { OAuthConfig } from "../../src/firstcontact/types.js";

const config: OAuthConfig = {
	clientId: "cid",
	clientSecret: "secret",
	callbackUrl: "https://app.test/cb",
};

function res(ok: boolean, status: number, body: unknown) {
	return { ok, status, json: async () => body };
}

/** Stub fetch with a queue of responses, recording every call. */
function stubFetch(...responses: Array<ReturnType<typeof res>>) {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	let i = 0;
	vi.stubGlobal("fetch", (url: string, init?: RequestInit) => {
		calls.push({ url, init });
		return Promise.resolve(responses[i++] ?? res(false, 500, {}));
	});
	return calls;
}

/** The form body of a recorded request, as a URLSearchParams. */
function body(call: { init?: RequestInit }): URLSearchParams {
	return call.init?.body as URLSearchParams;
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("warden > social drivers > where the user is sent", () => {
	it("sends each provider to its own authorize endpoint", () => {
		const url = (driver: { redirectUrl(state?: string): string }) =>
			new URL(driver.redirectUrl("st8"));

		expect(url(new DiscordDriver(config)).origin).toBe("https://discord.com");
		expect(url(new FacebookDriver(config)).hostname).toBe("www.facebook.com");
		expect(url(new LinkedInOpenidConnectDriver(config)).hostname).toBe(
			"www.linkedin.com",
		);
		expect(url(new SpotifyDriver(config)).hostname).toBe(
			"accounts.spotify.com",
		);
	});

	it("carries the client, the callback and the state", () => {
		const url = new URL(new DiscordDriver(config).redirectUrl("st8"));
		expect(url.searchParams.get("client_id")).toBe("cid");
		expect(url.searchParams.get("redirect_uri")).toBe("https://app.test/cb");
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("state")).toBe("st8");
	});

	it("requests each provider's default scopes, and takes an override", () => {
		expect(
			new URL(new SpotifyDriver(config).redirectUrl()).searchParams.get(
				"scope",
			),
		).toBe("user-read-email");
		expect(
			new URL(
				new LinkedInOpenidConnectDriver({
					...config,
					scopes: ["openid"],
				}).redirectUrl(),
			).searchParams.get("scope"),
		).toBe("openid");
	});

	it("appends the provider knobs a config adds", () => {
		const url = new URL(
			new DiscordDriver({
				...config,
				authorizeParams: { prompt: "none", guild_id: "42" },
			}).redirectUrl(),
		);
		expect(url.searchParams.get("prompt")).toBe("none");
		expect(url.searchParams.get("guild_id")).toBe("42");
	});
});

describe("warden > social drivers > PKCE", () => {
	it("refuses to send a user to X without a code verifier", () => {
		// The provider would reject the URL; failing here says why.
		expect(() => new TwitterDriver(config).redirectUrl("st8")).toThrow(
			/requires PKCE/,
		);
	});

	it("challenges with the S256 hash of the verifier, never the verifier", () => {
		const verifier = createCodeVerifier();
		const url = new URL(new TwitterDriver(config).redirectUrl("st8", verifier));

		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		const challenge = url.searchParams.get("code_challenge");
		expect(challenge).not.toBe(verifier);
		// Sending the verifier itself would defeat the whole exchange.
		expect(challenge).toBe(
			createHash("sha256").update(verifier).digest("base64url"),
		);
	});

	it("refuses the callback without the verifier it was redirected with", async () => {
		await expect(
			new TwitterDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(/requires PKCE/);
	});

	it("sends the verifier on the token exchange", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { data: { id: "1", username: "kaen" } }),
		);
		await new TwitterDriver(config).callback("code", "s", "s", "verifier-x");

		expect(body(calls[0]).get("code_verifier")).toBe("verifier-x");
	});

	it("mints a verifier long enough for every provider", () => {
		const verifier = createCodeVerifier();
		// RFC 7636 allows 43-128 characters, and 43 is what 32 random bytes give.
		expect(verifier.length).toBeGreaterThanOrEqual(43);
		expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(createCodeVerifier()).not.toBe(verifier);
	});
});

describe("warden > social drivers > how the client authenticates", () => {
	it("puts the secret in the body by default", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: "1" }),
		);
		await new DiscordDriver(config).callback("code", "s", "s");

		expect(body(calls[0]).get("client_secret")).toBe("secret");
		expect(calls[0].init?.headers).not.toHaveProperty("Authorization");
	});

	it("sends Basic credentials, and no secret in the body, where required", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: "1", images: [] }),
		);
		await new SpotifyDriver(config).callback("code", "s", "s");

		const headers = calls[0].init?.headers as Record<string, string>;
		expect(headers.Authorization).toBe(
			`Basic ${Buffer.from("cid:secret").toString("base64")}`,
		);
		// Both at once is what these providers reject outright.
		expect(body(calls[0]).get("client_secret")).toBeNull();
	});

	it("binds the code to the callback URL it was issued for", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: "1" }),
		);
		await new DiscordDriver(config).callback("code", "s", "s");

		expect(body(calls[0]).get("redirect_uri")).toBe("https://app.test/cb");
		expect(body(calls[0]).get("grant_type")).toBe("authorization_code");
	});

	it("keeps the refresh token and the lifetime when the provider issues them", async () => {
		stubFetch(
			res(true, 200, {
				access_token: "tok",
				refresh_token: "ref",
				expires_in: 3600,
			}),
			res(true, 200, { id: "1" }),
		);
		const out = await new DiscordDriver(config).callback("code", "s", "s");

		expect(out.token).toEqual({
			accessToken: "tok",
			refreshToken: "ref",
			expiresIn: 3600,
		});
	});
});

describe("warden > social drivers > reading the profile", () => {
	it("builds a Discord avatar URL from the hash, animated ones as gif", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, {
				id: "77",
				username: "kaen",
				email: "k@acme.test",
				avatar: "a_deadbeef",
			}),
		);
		const out = await new DiscordDriver(config).callback("code", "s", "s");

		expect(out.user.avatarUrl).toBe(
			"https://cdn.discordapp.com/avatars/77/a_deadbeef.gif",
		);
		expect(out.user.email).toBe("k@acme.test");
	});

	it("falls back to a Discord default avatar when the account has none", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: "4194304", username: "kaen" }),
		);
		const out = await new DiscordDriver(config).callback("code", "s", "s");

		// 4194304 >> 22 == 1
		expect(out.user.avatarUrl).toBe(
			"https://cdn.discordapp.com/embed/avatars/1.png",
		);
	});

	it("asks Facebook for the fields, which it returns nothing without", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, {
				id: "9",
				name: "Ada",
				email: "ada@acme.test",
				picture: { data: { url: "https://cdn/ada.png" } },
			}),
		);
		const out = await new FacebookDriver(config).callback("code", "s", "s");

		expect(calls[1].url).toContain("fields=");
		expect(out.user.avatarUrl).toBe("https://cdn/ada.png");
		expect(out.user.name).toBe("Ada");
	});

	it("reads the LinkedIn subject claim as the id", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, {
				sub: "abc",
				name: "Ada Lovelace",
				email: "ada@acme.test",
				picture: "https://cdn/ada.png",
			}),
		);
		const out = await new LinkedInOpenidConnectDriver(config).callback(
			"code",
			"s",
			"s",
		);

		// `id` does not exist on the OpenID Connect payload.
		expect(out.user.id).toBe("abc");
		expect(out.user.name).toBe("Ada Lovelace");
	});

	it("fetches the LinkedIn address separately on the member API", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, {
				id: "m1",
				localizedFirstName: "Ada",
				localizedLastName: "Lovelace",
			}),
			res(true, 200, {
				elements: [
					{ type: "EMAIL", "handle~": { emailAddress: "ada@acme.test" } },
				],
			}),
		);
		const out = await new LinkedInDriver(config).callback("code", "s", "s");

		expect(calls).toHaveLength(3);
		expect(out.user.name).toBe("Ada Lovelace");
		expect(out.user.email).toBe("ada@acme.test");
	});

	it("says which scope is missing when LinkedIn returns no address", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: "m1" }),
			res(true, 200, { elements: [] }),
		);
		// An empty address downstream reads as "this user has no email", which
		// is a different problem from "the app was never granted the scope".
		await expect(
			new LinkedInDriver(config).callback("code", "s", "s"),
		).rejects.toThrow(/r_emailaddress/);
	});

	it("takes the first Spotify image as the avatar", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, {
				id: "sp",
				display_name: "Ada",
				email: "ada@acme.test",
				images: [{ url: "https://cdn/1.png" }, { url: "https://cdn/2.png" }],
			}),
		);
		const out = await new SpotifyDriver(config).callback("code", "s", "s");

		expect(out.user.avatarUrl).toBe("https://cdn/1.png");
	});

	it("unwraps the X payload and falls back to the handle", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { data: { id: "x1", username: "kaen" } }),
		);
		const out = await new TwitterDriver(config).callback(
			"code",
			"s",
			"s",
			"verifier",
		);

		expect(out.user.id).toBe("x1");
		expect(out.user.name).toBe("kaen");
	});
});

describe("warden > social drivers > what the provider vouches for", () => {
	it("reports a verified address as verified", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, {
				sub: "g1",
				email: "ada@acme.test",
				email_verified: true,
				name: "Ada",
			}),
		);
		const out = await new GoogleDriver(config).callback("code", "s", "s");

		expect(out.user.emailVerificationState).toBe("verified");
	});

	it("reports an unverified address as unverified, not as silence", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, {
				sub: "g1",
				email: "ada@acme.test",
				email_verified: false,
			}),
		);
		const out = await new GoogleDriver(config).callback("code", "s", "s");

		// Linking an existing account on an unverified address hands it to
		// whoever typed that address at the provider.
		expect(out.user.emailVerificationState).toBe("unverified");
	});

	it("says unsupported where the provider claims nothing", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: "sp", email: "ada@acme.test", images: [] }),
		);
		const out = await new SpotifyDriver(config).callback("code", "s", "s");

		// Not the same as "yes" — Spotify simply does not say.
		expect(out.user.emailVerificationState).toBe("unsupported");
	});

	it("carries the handle beside the display name", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: "77", username: "kaen", global_name: "Kaen K." }),
		);
		const out = await new DiscordDriver(config).callback("code", "s", "s");

		expect(out.user.name).toBe("Kaen K.");
		expect(out.user.nickName).toBe("kaen");
	});
});

describe("warden > social drivers > GitHub private addresses", () => {
	it("reads the address from /user/emails when the profile hides it", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: 42, login: "kaen", email: null }),
			res(true, 200, [
				{ email: "old@acme.test", primary: false, verified: true },
				{ email: "ada@acme.test", primary: true, verified: true },
			]),
		);
		const out = await new GitHubDriver(config).callback("code", "s", "s");

		// Most accounts keep the address private, so /user returns null and the
		// sign-in would otherwise arrive with no address at all.
		expect(calls[2].url).toContain("/user/emails");
		expect(out.user.email).toBe("ada@acme.test");
		expect(out.user.emailVerificationState).toBe("verified");
	});

	it("does not ask for the address when the profile already carries one", async () => {
		const calls = stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: 42, login: "kaen", email: "ada@acme.test" }),
		);
		await new GitHubDriver(config).callback("code", "s", "s");

		expect(calls).toHaveLength(2);
	});

	it("signs the user in without an address when the scope was not granted", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: 42, login: "kaen", email: null }),
			res(false, 403, {}),
		);
		const out = await new GitHubDriver(config).callback("code", "s", "s");

		// A sign-in with no address is still a sign-in; refusing it would lock
		// out every account that declined `user:email`.
		expect(out.user.id).toBe("42");
		expect(out.user.email).toBe("");
	});

	it("prefers a verified address over an unverified primary", async () => {
		stubFetch(
			res(true, 200, { access_token: "tok" }),
			res(true, 200, { id: 42, login: "kaen", email: null }),
			res(true, 200, [
				{ email: "unverified@acme.test", primary: true, verified: false },
				{ email: "ada@acme.test", primary: false, verified: true },
			]),
		);
		const out = await new GitHubDriver(config).callback("code", "s", "s");

		expect(out.user.email).toBe("ada@acme.test");
	});
});

describe("warden > social drivers > a token already held", () => {
	it("reads a profile with no code to exchange", async () => {
		const calls = stubFetch(
			res(true, 200, { id: "sp", display_name: "Ada", images: [] }),
		);
		const user = await new SpotifyDriver(config).userFromToken("tok");

		// One call: the profile. No token endpoint involved.
		expect(calls).toHaveLength(1);
		expect(calls[0].url).toContain("api.spotify.com");
		expect(user.name).toBe("Ada");
	});
});

describe("warden > socials", () => {
	it("builds the driver each helper names", () => {
		expect(socials.discord(config)()).toBeInstanceOf(DiscordDriver);
		expect(socials.facebook(config)()).toBeInstanceOf(FacebookDriver);
		expect(socials.linkedin(config)()).toBeInstanceOf(LinkedInDriver);
		expect(socials.linkedinOpenidConnect(config)()).toBeInstanceOf(
			LinkedInOpenidConnectDriver,
		);
		expect(socials.spotify(config)()).toBeInstanceOf(SpotifyDriver);
		expect(socials.twitter(config)()).toBeInstanceOf(TwitterDriver);
	});
});
