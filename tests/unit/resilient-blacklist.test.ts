/**
 * The fallback was written ONLY when the primary failed, but consulted on every
 * failure — so it was a log of outages, not a record of revocations. A token
 * revoked while the primary was healthy was absent from it, and the first check
 * during a later outage let that logged-out token straight back in.
 */
import { describe, expect, it, vi } from "vitest";
import { ResilientBlacklistDriver } from "../../src/ResilientBlacklistDriver.js";
import {
	type BlacklistDriver,
	MemoryBlacklistDriver,
} from "../../src/TokenBlacklist.js";

/** A primary that can be taken down and brought back. */
function flakyPrimary() {
	const inner = new MemoryBlacklistDriver();
	let down = false;
	const driver: BlacklistDriver = {
		add: async (jti, expiresAt) => {
			if (down) throw new Error("KeyDB unreachable");
			return inner.add(jti, expiresAt);
		},
		has: async (jti) => {
			if (down) throw new Error("KeyDB unreachable");
			return inner.has(jti);
		},
		cleanup: async () => inner.cleanup(),
	};
	return {
		driver,
		takeDown: () => {
			down = true;
		},
		bringUp: () => {
			down = false;
		},
	};
}

const inAnHour = () => Date.now() + 3_600_000;

describe("warden > resilient blacklist", () => {
	it("still knows about a logout that happened before the outage", async () => {
		const primary = flakyPrimary();
		const blacklist = new ResilientBlacklistDriver(primary.driver, undefined, {
			onDegrade: () => {},
		});

		// The user logs out while everything is healthy.
		await blacklist.add("jti-1", inAnHour());
		expect(await blacklist.has("jti-1")).toBe(true);

		// KeyDB goes down. The same token must still be refused.
		primary.takeDown();
		expect(await blacklist.has("jti-1")).toBe(true);
	});

	it("still records a logout made during the outage", async () => {
		const primary = flakyPrimary();
		const blacklist = new ResilientBlacklistDriver(primary.driver, undefined, {
			onDegrade: () => {},
		});
		primary.takeDown();
		await blacklist.add("jti-2", inAnHour());
		expect(await blacklist.has("jti-2")).toBe(true);
	});

	it("does not fail the logout when the primary is down", async () => {
		const primary = flakyPrimary();
		const blacklist = new ResilientBlacklistDriver(primary.driver, undefined, {
			onDegrade: () => {},
		});
		primary.takeDown();
		await expect(blacklist.add("jti-3", inAnHour())).resolves.toBeUndefined();
	});

	it("lets an unknown token through during an outage (fail-open)", async () => {
		const primary = flakyPrimary();
		const blacklist = new ResilientBlacklistDriver(primary.driver, undefined, {
			onDegrade: () => {},
		});
		primary.takeDown();
		expect(await blacklist.has("never-revoked")).toBe(false);
	});

	it("honours a revocation another instance wrote to the primary", async () => {
		const shared = new MemoryBlacklistDriver();
		await shared.add("from-elsewhere", inAnHour());
		const blacklist = new ResilientBlacklistDriver(shared);
		expect(await blacklist.has("from-elsewhere")).toBe(true);
	});

	it("reports the first failure, then folds the repeats into a count", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const primary = flakyPrimary();
		primary.takeDown();
		const blacklist = new ResilientBlacklistDriver(primary.driver);
		for (let i = 0; i < 50; i++) await blacklist.has(`jti-${i}`);
		// One line, not fifty: a flood buries the outage it is reporting.
		expect(warn).toHaveBeenCalledTimes(1);
		warn.mockRestore();
	});
});
