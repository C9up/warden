import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ResilientBlacklistDriver } from "../../src/ResilientBlacklistDriver.js";
import {
	MemoryBlacklistDriver,
	TokenBlacklist,
} from "../../src/TokenBlacklist.js";

describe("warden > MemoryBlacklistDriver", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("returns false for an unknown jti", async () => {
		const driver = new MemoryBlacklistDriver();
		expect(await driver.has("missing")).toBe(false);
	});

	it("stores and reports a non-expired jti as present", async () => {
		const driver = new MemoryBlacklistDriver();
		const future = Date.now() + 60_000;
		await driver.add("jti-1", future);
		expect(await driver.has("jti-1")).toBe(true);
	});

	it("auto-deletes an expired jti when checked via has()", async () => {
		const driver = new MemoryBlacklistDriver();
		const past = Date.now() - 1_000;
		await driver.add("jti-stale", past);
		expect(await driver.has("jti-stale")).toBe(false);
		// has() purged it — a subsequent has() must still return false without
		// re-purging (otherwise the cleanup branch would run repeatedly).
		expect(await driver.has("jti-stale")).toBe(false);
	});

	it("cleanup() removes only expired entries", async () => {
		const driver = new MemoryBlacklistDriver();
		const now = Date.now();
		await driver.add("jti-keep", now + 60_000);
		await driver.add("jti-expired-1", now - 1);
		await driver.add("jti-expired-2", now - 1_000);
		await driver.cleanup();
		expect(await driver.has("jti-keep")).toBe(true);
		expect(await driver.has("jti-expired-1")).toBe(false);
		expect(await driver.has("jti-expired-2")).toBe(false);
	});
});

describe("warden > TokenBlacklist (driver delegation)", () => {
	it("delegates revoke/isRevoked/cleanup to the driver", async () => {
		const calls: Array<[string, unknown[]]> = [];
		const driver = {
			async add(jti: string, expiresAt: number) {
				calls.push(["add", [jti, expiresAt]]);
			},
			async has(jti: string) {
				calls.push(["has", [jti]]);
				return jti === "revoked";
			},
			async cleanup() {
				calls.push(["cleanup", []]);
			},
		};

		const bl = new TokenBlacklist(driver);
		await bl.revoke("revoked", 1234);
		expect(await bl.isRevoked("revoked")).toBe(true);
		expect(await bl.isRevoked("fresh")).toBe(false);
		await bl.cleanup();

		expect(calls).toEqual([
			["add", ["revoked", 1234]],
			["has", ["revoked"]],
			["has", ["fresh"]],
			["cleanup", []],
		]);
	});
});

/**
 * Expired revocations leave without anyone calling `cleanup()`.
 *
 * Entries left only on a `has()` of that exact jti or an explicit cleanup,
 * which nothing wires. Every logout and every `revoke()` added one, and the
 * resilient driver writes every revocation into its in-memory fallback, so a
 * long-lived process (or a user scripting login/logout) grew the heap without
 * bound.
 */
describe("warden > the in-memory revocation list sweeps itself", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("stays bounded across 100 000 short-lived revocations", async () => {
		const driver = new MemoryBlacklistDriver();
		for (let i = 0; i < 100_000; i++) {
			await driver.add(`jti-${i}`, Date.now() + 10);
			vi.advanceTimersByTime(1);
		}
		// Only the revocations still live (about ten) plus at most one sweep
		// interval of expired ones may remain.
		expect(driver.size).toBeLessThanOrEqual(128);
	});

	it("never drops a revocation that is still live", async () => {
		const driver = new MemoryBlacklistDriver();
		await driver.add("live", Date.now() + 3_600_000);
		for (let i = 0; i < 5_000; i++) {
			await driver.add(`short-${i}`, Date.now() + 1);
			vi.advanceTimersByTime(2);
		}
		expect(await driver.has("live")).toBe(true);
	});

	it("does not store a revocation that has already expired", async () => {
		const driver = new MemoryBlacklistDriver();
		await driver.add("stale", Date.now() - 1);
		expect(driver.size).toBe(0);
		expect(await driver.has("stale")).toBe(false);
	});

	it("bounds the resilient driver's fallback with a healthy primary", async () => {
		const fallback = new MemoryBlacklistDriver();
		const primary = new MemoryBlacklistDriver();
		const resilient = new ResilientBlacklistDriver(primary, fallback);
		for (let i = 0; i < 20_000; i++) {
			await resilient.add(`jti-${i}`, Date.now() + 10);
			vi.advanceTimersByTime(1);
		}
		expect(fallback.size).toBeLessThanOrEqual(128);
	});
});
