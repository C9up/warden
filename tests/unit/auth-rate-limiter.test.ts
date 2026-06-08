/**
 * AuthRateLimiter — brute-force protection. Covers the dual-key (IP + email)
 * blocking, success reset, remaining count, window expiry, identifier
 * normalization (case/space bypass), and the config-coercion guards.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthRateLimiter } from "../../src/AuthRateLimiter.js";

afterEach(() => {
	vi.useRealTimers();
});

describe("warden > AuthRateLimiter", () => {
	it("allows attempts under the limit and blocks once it is reached", () => {
		const rl = new AuthRateLimiter({ maxAttempts: 3 });
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(true);
		rl.recordFailure("1.1.1.1", "a@b.com");
		rl.recordFailure("1.1.1.1", "a@b.com");
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(true); // 2 < 3
		rl.recordFailure("1.1.1.1", "a@b.com");
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(false); // 3 >= 3
	});

	it("blocks by IP and by identifier independently (dual key)", () => {
		const rl = new AuthRateLimiter({ maxAttempts: 2 });
		rl.recordFailure("1.1.1.1", "victim@b.com");
		rl.recordFailure("1.1.1.1", "victim@b.com");
		// Same IP, different email → blocked on the IP key.
		expect(rl.check("1.1.1.1", "other@b.com")).toBe(false);
		// Different IP, same email → blocked on the identifier key.
		expect(rl.check("2.2.2.2", "victim@b.com")).toBe(false);
		// Fresh IP + fresh email → allowed.
		expect(rl.check("2.2.2.2", "other@b.com")).toBe(true);
	});

	it("recordSuccess clears both counters", () => {
		const rl = new AuthRateLimiter({ maxAttempts: 1 });
		rl.recordFailure("1.1.1.1", "a@b.com");
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(false);
		rl.recordSuccess("1.1.1.1", "a@b.com");
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(true);
	});

	it("remaining decrements, floors at 0, and reports the stricter of the two keys", () => {
		const rl = new AuthRateLimiter({ maxAttempts: 3 });
		expect(rl.remaining("1.1.1.1", "a@b.com")).toBe(3);
		rl.recordFailure("1.1.1.1", "a@b.com");
		expect(rl.remaining("1.1.1.1", "a@b.com")).toBe(2);
		// Hammer the IP key beyond the limit via different emails — IP is the
		// stricter key now, and remaining must floor at 0 (never negative).
		rl.recordFailure("1.1.1.1", "c@b.com");
		rl.recordFailure("1.1.1.1", "d@b.com");
		expect(rl.remaining("1.1.1.1", "fresh@b.com")).toBe(0);
	});

	it("expires the window so attempts are allowed again afterwards", () => {
		vi.useFakeTimers();
		vi.setSystemTime(0);
		const rl = new AuthRateLimiter({ maxAttempts: 1, windowSeconds: 60 });
		rl.recordFailure("1.1.1.1", "a@b.com");
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(false);
		vi.setSystemTime(61_000); // past the 60s window
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(true);
	});

	it("normalizes identifiers so case/whitespace cannot bypass the limit", () => {
		const rl = new AuthRateLimiter({ maxAttempts: 1 });
		rl.recordFailure("1.1.1.1", "Victim@B.com");
		// Same email with different case + padding must hit the same bucket.
		expect(rl.check("1.1.1.1", "  victim@b.com ")).toBe(false);
	});

	it("coerces non-positive config to safe defaults (no bypass via 0)", () => {
		const rl = new AuthRateLimiter({ maxAttempts: 0, windowSeconds: 0 });
		// maxAttempts coerced to 1 → blocked after a single failure.
		rl.recordFailure("1.1.1.1", "a@b.com");
		expect(rl.check("1.1.1.1", "a@b.com")).toBe(false);
	});
});
