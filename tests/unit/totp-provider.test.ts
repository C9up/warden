/**
 * TotpProvider — validated against the canonical RFC 6238 Appendix B test
 * vectors for SHA1/SHA256/SHA512, plus enrollment, skew window, and the
 * otpauth:// URI shape.
 */
import { describe, expect, it } from "vitest";
import { base32Encode } from "../../src/mfa/base32.js";
import { TotpProvider } from "../../src/mfa/TotpProvider.js";

// RFC 6238 Appendix B seeds (ASCII), one per algorithm.
const SEED_SHA1 = base32Encode(Buffer.from("12345678901234567890", "ascii"));
const SEED_SHA256 = base32Encode(
	Buffer.from("12345678901234567890123456789012", "ascii"),
);
const SEED_SHA512 = base32Encode(
	Buffer.from(
		"1234567890123456789012345678901234567890123456789012345678901234",
		"ascii",
	),
);

// [time in seconds, expected 8-digit TOTP]
const VECTORS = {
	SHA1: [
		[59, "94287082"],
		[1111111109, "07081804"],
		[1111111111, "14050471"],
		[1234567890, "89005924"],
		[2000000000, "69279037"],
		[20000000000, "65353130"],
	],
	SHA256: [
		[59, "46119246"],
		[1111111109, "68084774"],
		[1111111111, "67062674"],
		[1234567890, "91819424"],
		[2000000000, "90698825"],
		[20000000000, "77737706"],
	],
	SHA512: [
		[59, "90693936"],
		[1111111109, "25091201"],
		[1111111111, "99943326"],
		[1234567890, "93441116"],
		[2000000000, "38618901"],
		[20000000000, "47863826"],
	],
} as const;

const SEEDS = { SHA1: SEED_SHA1, SHA256: SEED_SHA256, SHA512: SEED_SHA512 };

describe("warden > TotpProvider (RFC 6238 vectors)", () => {
	for (const algorithm of ["SHA1", "SHA256", "SHA512"] as const) {
		const totp = new TotpProvider({ algorithm, digits: 8, period: 30 });
		const secret = SEEDS[algorithm];
		for (const [seconds, expected] of VECTORS[algorithm]) {
			it(`${algorithm} @ ${seconds}s → ${expected}`, () => {
				expect(totp.generate(secret, Number(seconds) * 1000)).toBe(expected);
			});
		}
	}
});

describe("warden > TotpProvider", () => {
	it("enrolls with a usable secret and otpauth URI", async () => {
		const totp = new TotpProvider();
		const { secret, uri } = totp.enroll("k@c9up.com", "Fluveo");
		expect(secret).toMatch(/^[A-Z2-7]+$/);
		expect(uri).toContain("otpauth://totp/Fluveo%3Ak%40c9up.com?");
		expect(uri).toContain("issuer=Fluveo");
		expect(uri).toContain("algorithm=SHA1");
		expect(uri).toContain("digits=6");
		// The freshly generated code must verify immediately.
		expect(await totp.verify(secret, totp.generate(secret))).toBe(true);
	});

	it("accepts a code from the previous step (clock skew, window=1)", async () => {
		const totp = new TotpProvider({ window: 1 });
		const { secret } = totp.enroll("a", "b");
		const now = 1_700_000_000_000;
		const prev = totp.generate(secret, now - 30_000);
		expect(await totp.verify(secret, prev, now)).toBe(true);
	});

	it("rejects a code two steps away (outside window=1)", async () => {
		const totp = new TotpProvider({ window: 1 });
		const { secret } = totp.enroll("a", "b");
		const now = 1_700_000_000_000;
		const stale = totp.generate(secret, now - 90_000);
		expect(await totp.verify(secret, stale, now)).toBe(false);
	});

	it("rejects wrong length and wrong code without throwing", async () => {
		const totp = new TotpProvider();
		const { secret } = totp.enroll("a", "b");
		expect(await totp.verify(secret, "123")).toBe(false);
		expect(await totp.verify(secret, "000000")).toBe(false);
	});

	it("tolerates spaces in user input", async () => {
		const totp = new TotpProvider();
		const { secret } = totp.enroll("a", "b");
		const code = totp.generate(secret);
		const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
		expect(await totp.verify(secret, spaced)).toBe(true);
	});

	it("rejects an out-of-range digit count at construction", () => {
		expect(() => new TotpProvider({ digits: 9 })).toThrow(/digits must be 6-8/);
	});
});

describe("warden > TOTP replay", () => {
	it("accepts a code once, then refuses it inside its own window", async () => {
		const totp = new TotpProvider();
		const { secret } = totp.enroll("a", "b");
		const code = totp.generate(secret);
		expect(await totp.verify(secret, code)).toBe(true);
		// RFC 6238 §5.2: a code is single-use. Without this it stayed valid for
		// the whole ±window — ~90s in which an intercepted code still works.
		expect(await totp.verify(secret, code)).toBe(false);
	});

	it("does not spend a code that did not match", async () => {
		const totp = new TotpProvider();
		const { secret } = totp.enroll("a", "b");
		expect(await totp.verify(secret, "000000")).toBe(false);
		expect(await totp.verify(secret, totp.generate(secret))).toBe(true);
	});

	it("keeps each secret's codes separate", async () => {
		const totp = new TotpProvider();
		const a = totp.enroll("a", "b").secret;
		const b = totp.enroll("c", "d").secret;
		expect(await totp.verify(a, totp.generate(a))).toBe(true);
		// A different user's code at the same step is untouched.
		expect(await totp.verify(b, totp.generate(b))).toBe(true);
	});

	it("can be turned off deliberately", async () => {
		const totp = new TotpProvider({ replayGuard: null });
		const { secret } = totp.enroll("a", "b");
		const code = totp.generate(secret);
		expect(await totp.verify(secret, code)).toBe(true);
		expect(await totp.verify(secret, code)).toBe(true);
	});

	it("takes a shared guard, for an app on several instances", async () => {
		const seen = new Map<string, number>();
		const shared = {
			used: (key: string) => seen.has(key),
			remember: (key: string) => {
				seen.set(key, 1);
			},
		};
		const one = new TotpProvider({ replayGuard: shared });
		const two = new TotpProvider({ replayGuard: shared });
		const { secret } = one.enroll("a", "b");
		const code = one.generate(secret);
		expect(await one.verify(secret, code)).toBe(true);
		// The second instance must refuse what the first already accepted.
		expect(await two.verify(secret, code)).toBe(false);
	});
});
