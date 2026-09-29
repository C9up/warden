/**
 * AuthRateLimiter — brute-force protection. An attempt is counted before the
 * credential is checked, under the IP and the identifier; a success clears
 * both. Covers the dual key, the window, identifier normalization, a
 * concurrent burst, the bounded memory store and the refused configurations.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryAttemptStore } from "../../src/AttemptStore.js";
import { AuthRateLimiter } from "../../src/AuthRateLimiter.js";

afterEach(() => {
	vi.useRealTimers();
});

const login = (ip: string, email: string) =>
	AuthRateLimiter.loginKeys(ip, email);

describe("warden > AuthRateLimiter", () => {
	it("lets attempts through up to the limit, then refuses them", async () => {
		const rl = new AuthRateLimiter({ maxAttempts: 2 });
		const keys = login("1.1.1.1", "a@b.com");
		expect(await rl.attempt(...keys)).toMatchObject({
			allowed: true,
			remaining: 1,
		});
		expect(await rl.attempt(...keys)).toMatchObject({
			allowed: true,
			remaining: 0,
		});
		expect((await rl.attempt(...keys)).allowed).toBe(false);
		expect(await rl.isBlocked(...keys)).toBe(true);
	});

	it("blocks by IP and by identifier independently (dual key)", async () => {
		const rl = new AuthRateLimiter({ maxAttempts: 2 });
		await rl.attempt(...login("1.1.1.1", "victim@b.com"));
		await rl.attempt(...login("1.1.1.1", "victim@b.com"));
		// Same IP, another account: the IP key is spent.
		expect((await rl.attempt(...login("1.1.1.1", "other@b.com"))).allowed).toBe(
			false,
		);
		// Another IP, same account: the identifier key is spent.
		expect(
			(await rl.attempt(...login("2.2.2.2", "victim@b.com"))).allowed,
		).toBe(false);
		expect((await rl.attempt(...login("3.3.3.3", "fresh@b.com"))).allowed).toBe(
			true,
		);
	});

	it("clears both keys after a success", async () => {
		const rl = new AuthRateLimiter({ maxAttempts: 1 });
		const keys = login("1.1.1.1", "a@b.com");
		await rl.attempt(...keys);
		expect(await rl.isBlocked(...keys)).toBe(true);
		await rl.clear(...keys);
		expect(await rl.isBlocked(...keys)).toBe(false);
	});

	it("starts over once the window has passed", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(0);
		const rl = new AuthRateLimiter({ maxAttempts: 1, windowSeconds: 60 });
		const keys = login("1.1.1.1", "a@b.com");
		await rl.attempt(...keys);
		expect((await rl.attempt(...keys)).allowed).toBe(false);
		vi.setSystemTime(61_000);
		expect((await rl.attempt(...keys)).allowed).toBe(true);
	});

	it("normalizes identifiers so case and padding cannot bypass the limit", async () => {
		const rl = new AuthRateLimiter({ maxAttempts: 1 });
		await rl.attempt(...login("1.1.1.1", "Victim@B.com"));
		expect(await rl.isBlocked(...login("1.1.1.1", "  victim@b.com "))).toBe(
			true,
		);
	});

	it("lets no more than the limit through a concurrent burst", async () => {
		const rl = new AuthRateLimiter({ maxAttempts: 1 });
		const decisions = await Promise.all(
			Array.from({ length: 20 }, () => rl.attempt("mfa:u1")),
		);
		// Checking first and counting after let all 20 through.
		expect(decisions.filter((d) => d.allowed)).toHaveLength(1);
	});

	it("refuses a limit that would not limit", () => {
		for (const config of [
			{ maxAttempts: Number.POSITIVE_INFINITY },
			{ maxAttempts: 0 },
			{ maxAttempts: 1.5 },
			{ windowSeconds: 0 },
			{ windowSeconds: Number.NaN },
		]) {
			expect(() => new AuthRateLimiter(config)).toThrow(
				/must be a positive whole number/,
			);
		}
	});
});

describe("warden > MemoryAttemptStore", () => {
	it("stays within its bound, evicting the oldest live windows", async () => {
		const store = new MemoryAttemptStore({ maxKeys: 3 });
		for (const key of ["a", "b", "c", "d"]) await store.increment(key, 60);
		expect(await store.count("a")).toBe(0);
		expect(await store.count("d")).toBe(1);
	});
});
