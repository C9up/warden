/**
 * RedisBlacklistDriver — a persistent JWT blacklist backed by Redis / KeyDB,
 * so logout revocation survives a process restart (unlike MemoryBlacklistDriver).
 *
 * Agnostic by construction: it depends on no Redis package. The caller injects
 * any ioredis-compatible client (KeyDB, Redis, a mock…) that exposes `set` with
 * an `"EX"` ttl and `exists`. Native key expiry does the housekeeping, so
 * `cleanup()` is a no-op.
 */

import type { BlacklistDriver } from "./TokenBlacklist.js";

/** The minimal ioredis-shaped surface this driver needs. */
export interface RedisLikeClient {
	set(
		key: string,
		value: string,
		mode: "EX",
		ttlSeconds: number,
	): Promise<unknown>;
	exists(key: string): Promise<number>;
}

export interface RedisBlacklistConfig {
	/** Key prefix for blacklist entries. Default `warden:blacklist:`. */
	prefix?: string;
}

export class RedisBlacklistDriver implements BlacklistDriver {
	readonly #client: RedisLikeClient;
	readonly #prefix: string;

	constructor(client: RedisLikeClient, config: RedisBlacklistConfig = {}) {
		this.#client = client;
		this.#prefix = config.prefix ?? "warden:blacklist:";
	}

	/**
	 * Blacklist a JTI until its natural expiry. Tokens already past `expiresAt`
	 * are skipped — there is nothing left to revoke.
	 */
	async add(jti: string, expiresAt: number): Promise<void> {
		const ttlSeconds = Math.ceil((expiresAt - Date.now()) / 1000);
		if (ttlSeconds <= 0) {
			return;
		}
		await this.#client.set(this.#key(jti), "1", "EX", ttlSeconds);
	}

	async has(jti: string): Promise<boolean> {
		return (await this.#client.exists(this.#key(jti))) > 0;
	}

	/** No-op: Redis/KeyDB evicts expired keys on its own. */
	async cleanup(): Promise<void> {}

	#key(jti: string): string {
		return `${this.#prefix}${jti}`;
	}
}
