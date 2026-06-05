import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
