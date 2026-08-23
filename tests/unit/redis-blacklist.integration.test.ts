/**
 * The JWT blacklist against a REAL Redis, wired through `quasarConnection()` —
 * the path an app uses.
 *
 * The unit suite verifies this driver against a `FakeRedis` we wrote ourselves,
 * which honours the TTL semantics *we believe* `SET … EX` has. That is the one
 * assumption worth checking for real: this is the mechanism that keeps a
 * revoked token revoked, and if the TTL is off a logged-out token quietly
 * becomes valid again.
 *
 * Gated on `REDIS_TEST_URL`; skipped without one.
 */
import { QuasarManager } from "@c9up/quasar";
import { clearQuasar, setQuasar } from "@c9up/quasar/services/main";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { quasarConnection } from "../../src/quasar.js";
import { RedisBlacklistDriver } from "../../src/RedisBlacklistDriver.js";

const url = process.env.REDIS_TEST_URL ?? "";
const describeRedis = url ? describe : describe.skip;

describeRedis("RedisBlacklistDriver against a live Redis", () => {
	const prefix = `warden-test:${process.pid}:`;
	const manager = new QuasarManager({
		connection: "main" as const,
		connections: { main: { url } },
	});

	function driver(): RedisBlacklistDriver {
		return new RedisBlacklistDriver(quasarConnection(), { prefix });
	}

	beforeEach(async () => {
		setQuasar(manager);
		const client = manager.connection();
		const keys = await client.keys(`${prefix}*`);
		if (keys.length > 0) await client.del(...keys);
	});

	afterAll(async () => {
		await manager.quitAll();
		clearQuasar(manager);
	});

	it("revokes a token and reports it revoked", async () => {
		const d = driver();
		expect(await d.has("jti-1")).toBe(false);

		await d.add("jti-1", Date.now() + 60_000);

		expect(await d.has("jti-1")).toBe(true);
	});

	it("survives a fresh driver — revocation is persisted, not in-process", async () => {
		await driver().add("jti-restart", Date.now() + 60_000);

		// A different driver instance, as after a process restart.
		expect(await driver().has("jti-restart")).toBe(true);
	});

	it("sets a TTL the server agrees with, so revocation cannot outlive the token", async () => {
		const d = driver();
		await d.add("jti-ttl", Date.now() + 60_000);

		const ttl = await manager.connection().ttl(`${prefix}jti-ttl`);
		// Real server-side TTL, not the fake's arithmetic: ~60s, never -1
		// (no expiry — the entry would outlive the token and pile up forever).
		expect(ttl).toBeGreaterThan(50);
		expect(ttl).toBeLessThanOrEqual(60);
	});

	it("stops reporting a token revoked once the real key expires", async () => {
		const d = driver();
		// One second of real TTL, then let the server actually evict it.
		await d.add("jti-short", Date.now() + 1_000);
		expect(await d.has("jti-short")).toBe(true);

		await expect
			.poll(() => d.has("jti-short"), { timeout: 5_000, interval: 200 })
			.toBe(false);
	});

	it("skips a token that already expired instead of writing a key", async () => {
		const d = driver();
		await d.add("jti-past", Date.now() - 1_000);

		// Nothing to revoke, so nothing stored — and no key without a TTL.
		expect(await d.has("jti-past")).toBe(false);
		expect(await manager.connection().exists(`${prefix}jti-past`)).toBe(0);
	});

	it("keeps separate tokens separate under the prefix", async () => {
		const d = driver();
		await d.add("jti-a", Date.now() + 60_000);

		expect(await d.has("jti-a")).toBe(true);
		expect(await d.has("jti-b")).toBe(false);
	});
});
