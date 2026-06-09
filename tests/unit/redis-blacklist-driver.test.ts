/**
 * RedisBlacklistDriver — verified against a fake ioredis-shaped client that
 * honours `"EX"` ttl semantics. Proves persistence, prefixing, TTL math, the
 * already-expired skip, and the no-op cleanup.
 */
import { describe, expect, it, vi } from "vitest";
import {
	RedisBlacklistDriver,
	type RedisLikeClient,
} from "../../src/RedisBlacklistDriver.js";

class FakeRedis implements RedisLikeClient {
	store = new Map<string, { value: string; expireAt: number }>();
	async set(
		key: string,
		value: string,
		_mode: "EX",
		ttlSeconds: number,
	): Promise<unknown> {
		this.store.set(key, { value, expireAt: Date.now() + ttlSeconds * 1000 });
		return "OK";
	}
	async exists(key: string): Promise<number> {
		const e = this.store.get(key);
		if (!e) return 0;
		if (e.expireAt < Date.now()) {
			this.store.delete(key);
			return 0;
		}
		return 1;
	}
}

describe("warden > RedisBlacklistDriver", () => {
	it("persists a revocation under the prefixed key and reads it back", async () => {
		const redis = new FakeRedis();
		const driver = new RedisBlacklistDriver(redis);
		await driver.add("jti-1", Date.now() + 60_000);

		expect(await driver.has("jti-1")).toBe(true);
		expect(await driver.has("jti-unknown")).toBe(false);
		expect([...redis.store.keys()]).toEqual(["warden:blacklist:jti-1"]);
	});

	it("sets an EX ttl derived from expiresAt", async () => {
		const redis = new FakeRedis();
		const spy = vi.spyOn(redis, "set");
		const driver = new RedisBlacklistDriver(redis);
		await driver.add("jti-2", Date.now() + 120_000);

		const [, , mode, ttl] = spy.mock.calls[0];
		expect(mode).toBe("EX");
		expect(ttl).toBeGreaterThan(118);
		expect(ttl).toBeLessThanOrEqual(120);
	});

	it("skips tokens that are already expired", async () => {
		const redis = new FakeRedis();
		const spy = vi.spyOn(redis, "set");
		const driver = new RedisBlacklistDriver(redis);
		await driver.add("jti-old", Date.now() - 1000);

		expect(spy).not.toHaveBeenCalled();
		expect(await driver.has("jti-old")).toBe(false);
	});

	it("honours a custom prefix", async () => {
		const redis = new FakeRedis();
		const driver = new RedisBlacklistDriver(redis, {
			prefix: "fluveo:revoked:",
		});
		await driver.add("jti-3", Date.now() + 60_000);
		expect([...redis.store.keys()]).toEqual(["fluveo:revoked:jti-3"]);
	});

	it("cleanup is a no-op (native expiry handles eviction)", async () => {
		const driver = new RedisBlacklistDriver(new FakeRedis());
		await expect(driver.cleanup()).resolves.toBeUndefined();
	});
});
