/**
 * Token lifetimes written the way upstream writes them.
 *
 * `expiresIn` upstream takes a number of seconds OR a duration string, so a
 * config copied out of an Adonis app carries `'1h'` or `'7 days'`. Accepting
 * only the number rejected such a config for a reason that had nothing to do
 * with authentication — and the failure looked like a type error at boot, not
 * like the migration detail it was.
 */
import { describe, expect, it } from "vitest";
import {
	parseDurationSeconds,
	resolveExpiresInSeconds,
} from "../../src/duration.js";
import { JwtStrategy } from "../../src/strategies/JwtStrategy.js";

describe("warden > duration strings", () => {
	it("reads the units echo reads, so `1d` means one thing in this repo", () => {
		expect(parseDurationSeconds("500ms")).toBe(0.5);
		expect(parseDurationSeconds("30s")).toBe(30);
		expect(parseDurationSeconds("15m")).toBe(900);
		expect(parseDurationSeconds("1h")).toBe(3600);
		expect(parseDurationSeconds("7 days")).toBe(604_800);
		expect(parseDurationSeconds("2w")).toBe(1_209_600);
	});

	it("treats a unit-less string as seconds", () => {
		// `JWT_EXPIRY=3600` reaches config as a string; reading it as
		// milliseconds would cut every token to 3.6 seconds.
		expect(parseDurationSeconds("3600")).toBe(3600);
	});

	it("refuses what it cannot read rather than guessing", () => {
		// A lifetime that quietly resolves to zero logs everyone out, and the
		// cause surfaces days later as "sessions are flaky".
		expect(() => parseDurationSeconds("soon")).toThrow(TypeError);
		expect(() => parseDurationSeconds("5 fortnights")).toThrow(TypeError);
		expect(() => parseDurationSeconds("")).toThrow(TypeError);
	});
});

describe("warden > resolving a lifetime", () => {
	it("accepts either spelling", () => {
		expect(resolveExpiresInSeconds("1h", undefined, 3600)).toBe(3600);
		expect(resolveExpiresInSeconds(900, undefined, 3600)).toBe(900);
		expect(resolveExpiresInSeconds(undefined, 900, 3600)).toBe(900);
	});

	it("falls back when neither is set", () => {
		expect(resolveExpiresInSeconds(undefined, undefined, 3600)).toBe(3600);
	});

	it("lets the portable spelling win when a config sets both", () => {
		// Such a config disagrees with itself; `expiresIn` is the name that
		// travels, so it is the one honoured.
		expect(resolveExpiresInSeconds("2h", 60, 3600)).toBe(7200);
	});

	it("refuses a non-positive lifetime", () => {
		// A token already expired when issued authenticates nobody, and the
		// symptom — every request 401s — points nowhere near the config.
		expect(() => resolveExpiresInSeconds(0, undefined, 3600)).toThrow(
			TypeError,
		);
		expect(() => resolveExpiresInSeconds(-1, undefined, 3600)).toThrow(
			TypeError,
		);
	});
});

describe("warden > the strategy honours the string", () => {
	/** Read `exp` and `iat` out of a signed token without verifying it. */
	function claims(token: string): { exp: number; iat: number } {
		const payload = token.split(".")[1] ?? "";
		return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
	}

	function strategy(config: Record<string, unknown>) {
		return new JwtStrategy({
			secret: "a-secret-long-enough-for-hs256-signing",
			findUser: async () => ({ id: "1" }),
			verifyCredentials: async () => ({ id: "1" }),
			...config,
		});
	}

	it("issues a token that lives as long as the string says", () => {
		const token = strategy({ expiresIn: "2h" }).signToken({ id: "1" });
		const { exp, iat } = claims(token);
		// The unit test above proves the parse; this proves the strategy
		// actually reaches for it instead of falling back to the default.
		expect(exp - iat).toBe(7200);
	});

	it("still honours the seconds-only spelling", () => {
		const token = strategy({ expiresInSeconds: 900 }).signToken({ id: "1" });
		const { exp, iat } = claims(token);
		expect(exp - iat).toBe(900);
	});
});
