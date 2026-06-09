/**
 * ResilientBlacklistDriver — primary delegation, and the fail-open + memory
 * fallback behaviour when the primary throws (add buffers, has honours in-outage
 * revocations but otherwise allows through).
 */
import { describe, expect, it, vi } from "vitest";
import { ResilientBlacklistDriver } from "../../src/ResilientBlacklistDriver.js";
import {
	type BlacklistDriver,
	MemoryBlacklistDriver,
} from "../../src/TokenBlacklist.js";

/** A primary whose failure can be toggled at will. */
class FlakyPrimary implements BlacklistDriver {
	failing = false;
	readonly inner = new MemoryBlacklistDriver();
	async add(jti: string, expiresAt: number): Promise<void> {
		if (this.failing) throw new Error("KeyDB down");
		await this.inner.add(jti, expiresAt);
	}
	async has(jti: string): Promise<boolean> {
		if (this.failing) throw new Error("KeyDB down");
		return this.inner.has(jti);
	}
	async cleanup(): Promise<void> {
		if (this.failing) throw new Error("KeyDB down");
		await this.inner.cleanup();
	}
}

const soon = () => Date.now() + 60_000;

describe("warden > ResilientBlacklistDriver", () => {
	it("delegates to the primary while it is healthy", async () => {
		const primary = new FlakyPrimary();
		const onDegrade = vi.fn();
		const driver = new ResilientBlacklistDriver(
			primary,
			new MemoryBlacklistDriver(),
			{ onDegrade },
		);
		await driver.add("jti-1", soon());
		expect(await driver.has("jti-1")).toBe(true);
		expect(onDegrade).not.toHaveBeenCalled();
	});

	it("buffers a revocation in the fallback when the primary fails", async () => {
		const primary = new FlakyPrimary();
		const fallback = new MemoryBlacklistDriver();
		const onDegrade = vi.fn();
		const driver = new ResilientBlacklistDriver(primary, fallback, {
			onDegrade,
		});

		primary.failing = true;
		await driver.add("jti-out", soon());
		// Primary still down on read → fallback catches the in-outage revocation.
		expect(await driver.has("jti-out")).toBe(true);
		expect(await fallback.has("jti-out")).toBe(true);
		expect(onDegrade).toHaveBeenCalledWith(
			expect.objectContaining({ op: "add" }),
		);
	});

	it("fails open for tokens it never revoked during an outage", async () => {
		const primary = new FlakyPrimary();
		const driver = new ResilientBlacklistDriver(primary);
		primary.failing = true;
		// Unknown token while the primary is unreachable → allowed through.
		expect(await driver.has("never-seen")).toBe(false);
	});

	it("cleanup tolerates a failing primary", async () => {
		const primary = new FlakyPrimary();
		primary.failing = true;
		const onDegrade = vi.fn();
		const driver = new ResilientBlacklistDriver(
			primary,
			new MemoryBlacklistDriver(),
			{ onDegrade },
		);
		await expect(driver.cleanup()).resolves.toBeUndefined();
		expect(onDegrade).toHaveBeenCalledWith(
			expect.objectContaining({ op: "cleanup" }),
		);
	});
});
