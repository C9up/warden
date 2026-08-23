/**
 * HTTP Basic (AdonisJS `basic_auth` guard). The credentials travel on EVERY
 * request, so the decoding has to be exact and the failure has to say as little
 * as possible.
 */
import { describe, expect, it } from "vitest";
import {
	BasicAuthStrategy,
	basicAuthChallenge,
	decodeBasicAuth,
	safeCompare,
} from "../../src/strategies/BasicAuthStrategy.js";

const strategy = new BasicAuthStrategy({
	realm: "Admin area",
	verifyCredentials: async (uid, password) =>
		uid === "ada" && password === "pa:ss word"
			? { id: "1", email: "ada@acme.test" }
			: null,
});

const header = (uid: string, password: string) =>
	`Basic ${Buffer.from(`${uid}:${password}`).toString("base64")}`;

describe("warden > basic auth decoding", () => {
	it("splits on the FIRST colon, so a password may contain colons", () => {
		expect(decodeBasicAuth(header("ada", "pa:ss word"))).toEqual({
			uid: "ada",
			password: "pa:ss word",
		});
	});

	it("refuses anything that is not a Basic header", () => {
		expect(decodeBasicAuth(undefined)).toBeNull();
		expect(decodeBasicAuth("Bearer abc")).toBeNull();
		expect(decodeBasicAuth("Basic")).toBeNull();
		// No colon at all is not a credential pair.
		expect(
			decodeBasicAuth(`Basic ${Buffer.from("nocolon").toString("base64")}`),
		).toBeNull();
	});
});

describe("warden > basic auth strategy", () => {
	it("authenticates a known pair", async () => {
		const result = await strategy.verify(header("ada", "pa:ss word"));
		expect(result.authenticated).toBe(true);
		expect(result.user?.email).toBe("ada@acme.test");
	});

	it("says the same thing for an unknown user and a wrong password", async () => {
		// Telling them apart turns the endpoint into a username oracle.
		const unknown = await strategy.verify(header("nobody", "x"));
		const wrong = await strategy.verify(header("ada", "wrong"));
		expect(unknown.authenticated).toBe(false);
		expect(wrong.authenticated).toBe(false);
		expect(unknown.error).toBe(wrong.error);
	});

	it("announces a realm the browser can show", () => {
		expect(strategy.challenge).toBe(
			'Basic realm="Admin area", charset="UTF-8"',
		);
		// A quote inside the realm would end the field early.
		expect(basicAuthChallenge('ev"il')).toBe(
			'Basic realm="evil", charset="UTF-8"',
		);
	});

	it("builds the header a test client sends", async () => {
		const { headers } = strategy.authenticateAsClient("ada", "pa:ss word");
		const result = await strategy.verify(headers?.authorization ?? "");
		expect(result.authenticated).toBe(true);
	});
});

describe("warden > safeCompare", () => {
	it("matches equal secrets and rejects the rest", () => {
		expect(safeCompare("abc", "abc")).toBe(true);
		expect(safeCompare("abc", "abd")).toBe(false);
		expect(safeCompare("abc", "abcd")).toBe(false);
	});
});
