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

/**
 * Where the client comes from. A resolver is what lets the blacklist name its
 * connection instead of being handed a client: config is read synchronously,
 * the first revocation check is not.
 */
export type RedisClientSource =
	| RedisLikeClient
	| (() => RedisLikeClient | Promise<RedisLikeClient>);

export class RedisBlacklistDriver implements BlacklistDriver {
	readonly #source: RedisClientSource;
	#resolved: RedisLikeClient | undefined;
	#pending: Promise<RedisLikeClient> | undefined;
	readonly #prefix: string;

	constructor(source: RedisClientSource, config: RedisBlacklistConfig = {}) {
		this.#source = source;
		this.#prefix = config.prefix ?? "warden:blacklist:";
	}

	/**
	 * The client, resolved once. Two requests racing on a cold start must not
	 * each open their own connection, so the in-flight promise is shared.
	 */
	async #client(): Promise<RedisLikeClient> {
		if (this.#resolved) return this.#resolved;
		if (typeof this.#source !== "function") {
			this.#resolved = this.#source;
			return this.#resolved;
		}
		if (!this.#pending) {
			const resolver = this.#source;
			// `finally`, not the success path: clearing it only on success left a
			// REJECTED promise in the slot, and every later call returned that
			// same rejection. One refused connection at boot — Redis still
			// starting, a network blip — and the blacklist never reconnected for
			// the life of the process, which for a revocation store means every
			// later check failing open or hard. Bay and echo already clear it
			// this way.
			this.#pending = Promise.resolve(resolver())
				.then((client) => {
					this.#resolved = client;
					return client;
				})
				.finally(() => {
					this.#pending = undefined;
				});
		}
		return this.#pending;
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
		const client = await this.#client();
		await client.set(this.#key(jti), "1", "EX", ttlSeconds);
	}

	async has(jti: string): Promise<boolean> {
		const client = await this.#client();
		return (await client.exists(this.#key(jti))) > 0;
	}

	/** No-op: Redis/KeyDB evicts expired keys on its own. */
	async cleanup(): Promise<void> {}

	#key(jti: string): string {
		return `${this.#prefix}${jti}`;
	}
}
