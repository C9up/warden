import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	generateRefreshToken,
	MemoryRefreshTokenDriver,
	type StoredRefreshToken,
} from "../../src/RefreshTokenStore.js";

function makeStored(
	overrides: Partial<StoredRefreshToken> = {},
): StoredRefreshToken {
	return {
		token: "tok",
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

	it("returns null for an unknown token", async () => {
		const driver = new MemoryRefreshTokenDriver();
		expect(await driver.find("nope")).toBe(null);
	});

	it("stores and finds a non-expired token", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const token = makeStored({ token: "abc", userId: 42 });
		await driver.store(token);
		expect(await driver.find("abc")).toEqual(token);
	});

	it("auto-deletes an expired token when find() is called", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(
			makeStored({ token: "stale", expiresAt: Date.now() - 1 }),
		);
		expect(await driver.find("stale")).toBe(null);
		// purged: a fresh store with the same key must succeed afterwards.
		await driver.store(makeStored({ token: "stale" }));
		expect(await driver.find("stale")).not.toBe(null);
	});

	it("revoke() removes a single token", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ token: "a" }));
		await driver.store(makeStored({ token: "b" }));
		await driver.revoke("a");
		expect(await driver.find("a")).toBe(null);
		expect(await driver.find("b")).not.toBe(null);
	});

	it("revokeAllForUser() removes only matching userId tokens", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ token: "u1-a", userId: "u1" }));
		await driver.store(makeStored({ token: "u1-b", userId: "u1" }));
		await driver.store(makeStored({ token: "u2-a", userId: "u2" }));
		await driver.revokeAllForUser("u1");
		expect(await driver.find("u1-a")).toBe(null);
		expect(await driver.find("u1-b")).toBe(null);
		expect(await driver.find("u2-a")).not.toBe(null);
	});

	it("revokeAllForUser() supports numeric userId equality", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ token: "n42", userId: 42 }));
		await driver.store(makeStored({ token: "n7", userId: 7 }));
		await driver.revokeAllForUser(42);
		expect(await driver.find("n42")).toBe(null);
		expect(await driver.find("n7")).not.toBe(null);
	});

	it("cleanup() removes expired tokens only", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const now = Date.now();
		await driver.store(makeStored({ token: "fresh", expiresAt: now + 60_000 }));
		await driver.store(makeStored({ token: "stale", expiresAt: now - 1 }));
		await driver.cleanup();
		expect(await driver.find("fresh")).not.toBe(null);
		expect(await driver.find("stale")).toBe(null);
	});
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
