/**
 * Quasar retires a connection whose retry strategy gave up (about three
 * seconds of outage with the generated config) and hands out a fresh one on
 * the next `connection(name)`. The Redis-backed stores kept the first one, so
 * after a short outage every login failed, the revocation list ran on its
 * fallback and every TOTP code was refused — "Connection is closed." until the
 * process restarted, even once Redis was back.
 */
import { describe, expect, it, vi } from "vitest";
import {
	type AttemptRedisClient,
	RedisAttemptStore,
} from "../../src/AttemptStore.js";
import {
	RedisTotpReplayGuard,
	type ReplayRedisClient,
} from "../../src/mfa/TotpProvider.js";
import {
	RedisBlacklistDriver,
	type RedisLikeClient,
} from "../../src/RedisBlacklistDriver.js";

function attemptClient(status: string) {
	return {
		status,
		incr: vi.fn(async () => 1),
		expire: vi.fn(async () => 1),
		ttl: vi.fn(async () => 60),
		get: vi.fn(async (): Promise<string | null> => null),
		del: vi.fn(async () => 1),
	};
}

function blacklistClient(status: string) {
	return {
		status,
		set: vi.fn(async () => "OK"),
		exists: vi.fn(async () => 0),
	};
}

function replayClient(status: string) {
	return { status, set: vi.fn(async (): Promise<unknown> => "OK") };
}

describe("warden > a Redis store whose connection ended for good", () => {
	it("RedisAttemptStore asks its resolver again", async () => {
		const first = attemptClient("ready");
		const second = attemptClient("ready");
		const resolver = vi
			.fn<() => Promise<AttemptRedisClient>>()
			.mockResolvedValueOnce(first)
			.mockResolvedValueOnce(second);
		const store = new RedisAttemptStore(resolver);

		await store.count("login:a");
		first.status = "end";
		await store.count("login:a");

		expect(resolver).toHaveBeenCalledTimes(2);
		expect(second.get).toHaveBeenCalledOnce();
	});

	it("RedisBlacklistDriver asks its resolver again", async () => {
		const first = blacklistClient("ready");
		const second = blacklistClient("ready");
		const resolver = vi
			.fn<() => RedisLikeClient>()
			.mockReturnValueOnce(first)
			.mockReturnValueOnce(second);
		const driver = new RedisBlacklistDriver(resolver);

		await driver.has("jti-1");
		first.status = "end";
		await driver.has("jti-1");

		expect(resolver).toHaveBeenCalledTimes(2);
		expect(second.exists).toHaveBeenCalledOnce();
	});

	it("RedisTotpReplayGuard asks its resolver again", async () => {
		const first = replayClient("ready");
		const second = replayClient("ready");
		const resolver = vi
			.fn<() => Promise<ReplayRedisClient>>()
			.mockResolvedValueOnce(first)
			.mockResolvedValueOnce(second);
		const guard = new RedisTotpReplayGuard(resolver);

		await guard.claim("user:123456", 30_000);
		first.status = "end";
		await guard.claim("user:654321", 30_000);

		expect(resolver).toHaveBeenCalledTimes(2);
		expect(second.set).toHaveBeenCalledOnce();
	});

	it("keeps a client that closed but reconnects by itself", async () => {
		const client = blacklistClient("ready");
		const resolver = vi.fn(() => client);
		const driver = new RedisBlacklistDriver(resolver);

		await driver.has("jti-1");
		client.status = "close";
		await driver.has("jti-1");

		expect(resolver).toHaveBeenCalledOnce();
	});

	it("keeps a client handed in directly: replacing it is the caller's call", async () => {
		const attempts = attemptClient("end");
		const blacklist = blacklistClient("end");
		const replay = replayClient("end");

		await new RedisAttemptStore(attempts).count("login:a");
		await new RedisBlacklistDriver(blacklist).has("jti-1");
		await new RedisTotpReplayGuard(replay).claim("user:123456", 30_000);

		expect(attempts.get).toHaveBeenCalledOnce();
		expect(blacklist.exists).toHaveBeenCalledOnce();
		expect(replay.set).toHaveBeenCalledOnce();
	});
});
