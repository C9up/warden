/**
 * OAuth 1.0a signing.
 *
 * The base string is the whole game: both sides hash exactly those bytes, and
 * a mismatch surfaces as an opaque 401 from the provider with nothing to go
 * on. The first test pins it against the worked example in RFC 5849 §3.4.1.1,
 * so it is checked against the specification rather than against itself.
 */
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	authorizationHeader,
	baseOauthParams,
	nonce,
	type Param,
	parseFormBody,
	percentEncode,
	sign,
	signatureBaseString,
} from "../../src/firstcontact/oauth1.js";

describe("warden > oauth1 > signature base string", () => {
	it("matches the worked example in RFC 5849", () => {
		const base = signatureBaseString({
			method: "post",
			url: "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b",
			params: [
				["c2", ""],
				["a3", "2 q"],
			],
			oauth: [
				["oauth_consumer_key", "9djdj82h48djs9d2"],
				["oauth_token", "kkk9d7dh3k39sjv7"],
				["oauth_signature_method", "HMAC-SHA1"],
				["oauth_timestamp", "137131201"],
				["oauth_nonce", "7d8f3e4a"],
			],
			consumerSecret: "irrelevant",
		});

		expect(base).toBe(
			"POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7",
		);
	});

	it("does not depend on how an escape was spelled", () => {
		const of = (url: string) =>
			signatureBaseString({
				method: "GET",
				url,
				oauth: [["oauth_nonce", "n"]],
				consumerSecret: "s",
			});

		// `a=b c` and `a=b%20c` are the same request; a signature that told them
		// apart would fail for one of the two spellings.
		expect(of("https://x.test/p?a=b%20c")).toBe(of("https://x.test/p?a=b+c"));
	});

	it("drops the query and the fragment from the signed URL", () => {
		const base = signatureBaseString({
			method: "GET",
			url: "https://x.test/p?a=1#frag",
			oauth: [],
			consumerSecret: "s",
		});

		expect(base.startsWith("GET&https%3A%2F%2Fx.test%2Fp&")).toBe(true);
		expect(base).not.toContain("frag");
	});
});

describe("warden > oauth1 > percent encoding", () => {
	it("escapes the characters encodeURIComponent leaves alone", () => {
		// These five are the classic reason a hand-rolled OAuth1 client fails.
		expect(percentEncode("!'()*")).toBe("%21%27%28%29%2A");
	});

	it("leaves the unreserved set untouched", () => {
		expect(percentEncode("aZ09-._~")).toBe("aZ09-._~");
	});

	it("escapes a space as %20, never as +", () => {
		expect(percentEncode("r b")).toBe("r%20b");
	});
});

describe("warden > oauth1 > signing key", () => {
	it("is the consumer secret and the token secret, both encoded", () => {
		const input = {
			method: "GET",
			url: "https://x.test/p",
			oauth: [["oauth_nonce", "n"]] as Param[],
			consumerSecret: "cs&x",
			tokenSecret: "ts=y",
		};
		const expected = createHmac("sha1", "cs%26x&ts%3Dy")
			.update(signatureBaseString(input))
			.digest("base64");

		expect(sign(input)).toBe(expected);
	});

	it("still ends in & when there is no token yet", () => {
		// The very first call has no token; the key is `secret&`, not `secret`.
		const input = {
			method: "POST",
			url: "https://x.test/request_token",
			oauth: [] as Param[],
			consumerSecret: "cs",
		};
		const expected = createHmac("sha1", "cs&")
			.update(signatureBaseString(input))
			.digest("base64");

		expect(sign(input)).toBe(expected);
	});
});

describe("warden > oauth1 > the Authorization header", () => {
	it("carries the oauth parameters and the signature, quoted and encoded", () => {
		const header = authorizationHeader({
			method: "POST",
			url: "https://x.test/request_token",
			oauth: baseOauthParams({
				consumerKey: "key",
				timestamp: 137131201,
				nonce: "abc",
			}),
			consumerSecret: "cs",
		});

		expect(header.startsWith("OAuth ")).toBe(true);
		expect(header).toContain('oauth_consumer_key="key"');
		expect(header).toContain('oauth_signature_method="HMAC-SHA1"');
		expect(header).toContain('oauth_version="1.0"');
		expect(header).toMatch(/oauth_signature="[A-Za-z0-9%]+"/);
	});

	it("omits oauth_token until there is one", () => {
		const params = baseOauthParams({
			consumerKey: "key",
			timestamp: 1,
			nonce: "n",
		});

		expect(params.some(([key]) => key === "oauth_token")).toBe(false);
		expect(
			baseOauthParams({
				consumerKey: "key",
				token: "t",
				timestamp: 1,
				nonce: "n",
			}).some(([key]) => key === "oauth_token"),
		).toBe(true);
	});
});

describe("warden > oauth1 > responses", () => {
	it("reads the form-encoded body the token endpoints answer with", () => {
		// Not JSON — this is the one place OAuth1 differs visibly on the wire.
		expect(
			parseFormBody(
				"oauth_token=t&oauth_token_secret=s&oauth_callback_confirmed=true",
			),
		).toEqual({
			oauth_token: "t",
			oauth_token_secret: "s",
			oauth_callback_confirmed: "true",
		});
	});

	it("mints a fresh nonce each time", () => {
		expect(nonce()).not.toBe(nonce());
		expect(nonce()).toMatch(/^[0-9a-f]{32}$/);
	});
});
