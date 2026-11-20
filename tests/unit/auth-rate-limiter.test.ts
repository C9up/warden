/**
 * AuthRateLimiter — brute-force protection. An attempt is counted before the
 * credential is checked, under the IP and the identifier; a success clears
 * both. Covers the dual key, the window, identifier normalization, a
 * concurrent burst, the bounded memory store and the refused configurations.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type AttemptCount,
	type AttemptStore,
	MemoryAttemptStore,
} from "../../src/AttemptStore.js";
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

/** A memory store that also remembers every key it was asked to count. */
class RecordingStore implements AttemptStore {
	readonly #inner = new MemoryAttemptStore();
	readonly keys = new Set<string>();

	increment(key: string, windowSeconds: number): Promise<AttemptCount> {
		this.keys.add(key);
		return this.#inner.increment(key, windowSeconds);
	}

	count(key: string): Promise<number> {
		return this.#inner.count(key);
	}

	reset(key: string): Promise<void> {
		return this.#inner.reset(key);
	}
}

describe("warden > AuthRateLimiter > a throttled client cannot grow the store", () => {
	it("stops at the first refused key, so a throttled IP mints no identifier keys", async () => {
		const store = new RecordingStore();
		const rl = new AuthRateLimiter({ maxAttempts: 5, store });
		for (let i = 0; i < 2000; i++) {
			await rl.attempt(...login("203.0.113.9", `user${i}@x.test`));
		}
		// One IP key, and only the identifiers tried while the IP had budget.
		expect(store.keys.size).toBe(1 + 5);
	});

	it("leaves a full memory store's room to other clients", async () => {
		const limiter = new AuthRateLimiter({
			store: new MemoryAttemptStore({ maxKeys: 1000 }),
		});
		for (let i = 0; i < 2000; i++) {
			await limiter.attempt(...login("203.0.113.9", `user${i}@x.test`));
		}
		const decision = await limiter.attempt(
			...login("198.51.100.1", "admin@corp.test"),
		);
		expect(decision.allowed).toBe(true);
	});

	it("does not count the keys after the refused one", async () => {
		const rl = new AuthRateLimiter({ maxAttempts: 1 });
		await rl.attempt(...login("1.1.1.1", "a@b.com"));
		const refused = await rl.attempt(...login("1.1.1.1", "b@b.com"));
		expect(refused).toMatchObject({ allowed: false, remaining: 0 });
		expect(refused.retryAfterSeconds).toBeGreaterThan(0);
		// b@b.com was never counted: from a fresh IP it still has its attempt.
		expect((await rl.attempt(...login("2.2.2.2", "b@b.com"))).allowed).toBe(
			true,
		);
	});

	it("keys an identifier by a fixed-size digest, whatever its length", () => {
		const huge = `${"a".repeat(1_000_000)}@x.io`;
		const [ip, id] = login("203.0.113.9", huge);
		expect(ip).toBe("ip:203.0.113.9");
		// Asserted as booleans: a failure must not print a 1 MB key.
		expect(/^id:[A-Za-z0-9_-]{43}$/.test(id ?? "")).toBe(true);
		expect(login("1.1.1.1", `  ${huge.toUpperCase()} `)[1] === id).toBe(true);
		expect(login("1.1.1.1", "b@x.io")[1] === id).toBe(false);
	});
});

describe("warden > MemoryAttemptStore", () => {
	it("stays within its bound by refusing a new key, never evicting a live one", async () => {
		const store = new MemoryAttemptStore({ maxKeys: 3 });
		for (const key of ["a", "b", "c"]) await store.increment(key, 60);

		const refused = await store.increment("d", 60);

		expect(refused.count).toBe(Number.POSITIVE_INFINITY);
		expect(refused.resetSeconds).toBeGreaterThan(0);
		expect(refused.resetSeconds).toBeLessThanOrEqual(60);
		// Every live counter is still there; the refused key was not stored.
		expect(await store.count("a")).toBe(1);
		expect(await store.count("d")).toBe(0);
	});

	it("makes room once a window has expired", async () => {
		vi.useFakeTimers();
		try {
			const store = new MemoryAttemptStore({ maxKeys: 2 });
			await store.increment("short", 1);
			await store.increment("long", 600);
			vi.advanceTimersByTime(2_000);

			expect((await store.increment("new", 60)).count).toBe(1);
			expect(await store.count("long")).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("does not let a flood of identifiers lift a victim's lockout", async () => {
		const limiter = new AuthRateLimiter({
			maxAttempts: 3,
			windowSeconds: 900,
			store: new MemoryAttemptStore({ maxKeys: 10 }),
		});
		const victim = AuthRateLimiter.loginKeys("10.0.0.1", "victim@example.com");
		for (let i = 0; i < 3; i++) await limiter.attempt(...victim);
		expect((await limiter.attempt(...victim)).allowed).toBe(false);

		// The attacker sprays made-up identifiers from many addresses.
		for (let i = 0; i < 20; i++) {
			await limiter.attempt(
				...AuthRateLimiter.loginKeys(`10.1.0.${i}`, `junk-${i}@example.com`),
			);
		}

		expect((await limiter.attempt(...victim)).allowed).toBe(false);
		expect(await limiter.isBlocked(...victim)).toBe(true);
	});

	it("refuses an attempt it could not count", async () => {
		const limiter = new AuthRateLimiter({
			maxAttempts: 5,
			store: new MemoryAttemptStore({ maxKeys: 1 }),
		});
		await limiter.attempt("ip:1.1.1.1");

		const decision = await limiter.attempt("ip:2.2.2.2");

		expect(decision.allowed).toBe(false);
		expect(decision.remaining).toBe(0);
		expect(decision.retryAfterSeconds).toBeGreaterThan(0);
	});
});
