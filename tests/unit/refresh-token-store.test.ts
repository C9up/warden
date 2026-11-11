import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	generateRefreshToken,
	hashRefreshToken,
	MemoryRefreshTokenDriver,
	mintRefreshToken,
	type StoredRefreshToken,
} from "../../src/RefreshTokenStore.js";

function makeStored(
	overrides: Partial<StoredRefreshToken> = {},
): StoredRefreshToken {
	return {
		hash: hashRefreshToken("tok"),
		userId: "user-1",
		expiresAt: Date.now() + 60_000,
		createdAt: Date.now(),
		...overrides,
	};
}

describe("warden > MemoryRefreshTokenDriver", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("returns null for an unknown hash", async () => {
		const driver = new MemoryRefreshTokenDriver();
		expect(await driver.find(hashRefreshToken("nope"))).toBe(null);
	});

	it("stores and finds a non-expired token by its hash", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const token = makeStored({ hash: hashRefreshToken("abc"), userId: 42 });
		await driver.store(token);
		expect(await driver.find(hashRefreshToken("abc"))).toEqual(token);
	});

	it("auto-deletes an expired token when find() is called", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const hash = hashRefreshToken("stale");
		await driver.store(makeStored({ hash, expiresAt: Date.now() - 1 }));
		expect(await driver.find(hash)).toBe(null);
		// purged: a fresh store with the same key must succeed afterwards.
		await driver.store(makeStored({ hash }));
		expect(await driver.find(hash)).not.toBe(null);
	});

	it("treats an expiry that is not a number as expired", async () => {
		// `expiresAt < now` is false for NaN: the row never expired.
		const driver = new MemoryRefreshTokenDriver();
		const hash = hashRefreshToken("nan");
		await driver.store(makeStored({ hash, expiresAt: Number.NaN }));
		expect(await driver.find(hash)).toBe(null);
	});

	it("revoke() removes a single token", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const a = hashRefreshToken("a");
		const b = hashRefreshToken("b");
		await driver.store(makeStored({ hash: a }));
		await driver.store(makeStored({ hash: b }));
		await driver.revoke(a);
		expect(await driver.find(a)).toBe(null);
		expect(await driver.find(b)).not.toBe(null);
	});

	it("revokeAllForUser() removes only matching userId tokens", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const [u1a, u1b, u2a] = ["u1-a", "u1-b", "u2-a"].map(hashRefreshToken);
		await driver.store(makeStored({ hash: u1a, userId: "u1" }));
		await driver.store(makeStored({ hash: u1b, userId: "u1" }));
		await driver.store(makeStored({ hash: u2a, userId: "u2" }));
		await driver.revokeAllForUser("u1");
		expect(await driver.find(u1a ?? "")).toBe(null);
		expect(await driver.find(u1b ?? "")).toBe(null);
		expect(await driver.find(u2a ?? "")).not.toBe(null);
	});

	it("revokeAllForUser() matches a numeric id against a string one, both ways", async () => {
		// `1 === "1"` is false: a sign-out-everywhere for user 1 missed the rows
		// a driver had stored with the id as a string, leaving them usable.
		const driver = new MemoryRefreshTokenDriver();
		const asString = hashRefreshToken("as-string");
		const asNumber = hashRefreshToken("as-number");
		const other = hashRefreshToken("other");
		await driver.store(makeStored({ hash: asString, userId: "1" }));
		await driver.store(makeStored({ hash: asNumber, userId: 7 }));
		await driver.store(makeStored({ hash: other, userId: 2 }));

		await driver.revokeAllForUser(1);
		await driver.revokeAllForUser("7");

		expect(await driver.find(asString)).toBe(null);
		expect(await driver.find(asNumber)).toBe(null);
		expect(await driver.find(other)).not.toBe(null);
	});

	it("cleanup() removes expired tokens only", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const now = Date.now();
		const fresh = hashRefreshToken("fresh");
		const stale = hashRefreshToken("stale");
		await driver.store(makeStored({ hash: fresh, expiresAt: now + 60_000 }));
		await driver.store(makeStored({ hash: stale, expiresAt: now - 1 }));
		await driver.cleanup();
		expect(await driver.find(fresh)).not.toBe(null);
		expect(await driver.find(stale)).toBe(null);
	});
});

/**
 * A refresh token is a bearer credential: only its hash is persisted, so a dump
 * of the table is not a set of working tokens.
 */
describe("warden > refresh tokens are stored hashed", () => {
	it("mints a value whose stored row holds only its sha256", () => {
		const { value, stored } = mintRefreshToken("u1", 3600);

		expect(stored.hash).toBe(hashRefreshToken(value));
		expect(stored.hash).toMatch(/^[0-9a-f]{64}$/);
		expect(JSON.stringify(stored)).not.toContain(value);
		expect(stored.userId).toBe("u1");
		expect(stored.expiresAt - stored.createdAt).toBe(3_600_000);
	});

	it("a dumped row does not authenticate: the hash is not the token", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const { value, stored } = mintRefreshToken("u1", 3600);
		await driver.store(stored);

		// The presented token is found through its hash...
		expect(await driver.find(hashRefreshToken(value))).toEqual(stored);
		// ...and the stored hash, presented as a token, is not.
		expect(await driver.find(hashRefreshToken(stored.hash))).toBe(null);
	});

	it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
		"refuses a lifetime of %s seconds",
		(ttl) => {
			expect(() => mintRefreshToken("u1", ttl)).toThrow(
				expect.objectContaining({ code: "E_WARDEN_TOKEN_TTL_INVALID" }),
			);
		},
	);
});

describe("warden > generateRefreshToken", () => {
	it("returns a 64-char base64url string with no padding", () => {
		const token = generateRefreshToken();
		// 48 bytes -> 64 base64url chars (no `=` padding, no `+/` chars)
		expect(token).toMatch(/^[A-Za-z0-9_-]{64}$/);
	});

	it("produces distinct tokens across calls (entropy sanity check)", () => {
		const seen = new Set<string>();
		for (let i = 0; i < 50; i++) seen.add(generateRefreshToken());
		expect(seen.size).toBe(50);
	});
});
