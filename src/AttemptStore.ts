/**
 * Where failed-attempt counters live — for the login throttle
 * ({@link AuthRateLimiter}) and the MFA lockout (`MfaManager`).
 *
 * The count is taken BEFORE the credential is checked, by one atomic
 * increment. Checking "is it locked?" first and recording the failure after
 * let a burst of concurrent attempts all read "not locked" and all reach the
 * verifier; an increment that returns the new count cannot be raced that way.
 *
 * The memory store is one process's; a cluster shares {@link RedisAttemptStore}
 * so a lockout holds whichever instance the next attempt lands on.
 */

/** A window of attempts counted under one key. */
export interface AttemptCount {
	/** Attempts in the current window, this one included. */
	count: number;
	/** Seconds until the window ends and the count starts over. */
	resetSeconds: number;
}

export interface AttemptStore {
	/**
	 * Count one attempt under `key`, atomically, and return the count so far.
	 * The window starts at the first attempt and lasts `windowSeconds`.
	 */
	increment(key: string, windowSeconds: number): Promise<AttemptCount>;
	/** The attempts counted under `key` in its current window (0 if none). */
	count(key: string): Promise<number>;
	/** Forget `key`'s attempts — after a success. */
	reset(key: string): Promise<void>;
}

/** Most keys the memory store holds before it makes room. */
const DEFAULT_MAX_KEYS = 100_000;

/** In this process's memory, bounded. Not shared across instances. */
export class MemoryAttemptStore implements AttemptStore {
	readonly #entries = new Map<string, { count: number; resetAt: number }>();
	readonly #maxKeys: number;

	constructor(options: { maxKeys?: number } = {}) {
		this.#maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
	}

	async increment(key: string, windowSeconds: number): Promise<AttemptCount> {
		const now = Date.now();
		let entry = this.#entries.get(key);
		if (entry === undefined || entry.resetAt <= now) {
			this.#entries.delete(key);
			this.#makeRoom(now);
			entry = { count: 0, resetAt: now + windowSeconds * 1000 };
			this.#entries.set(key, entry);
		}
		entry.count++;
		return {
			count: entry.count,
			resetSeconds: Math.ceil((entry.resetAt - now) / 1000),
		};
	}

	async count(key: string): Promise<number> {
		const entry = this.#entries.get(key);
		if (entry === undefined) return 0;
		if (entry.resetAt <= Date.now()) {
			this.#entries.delete(key);
			return 0;
		}
		return entry.count;
	}

	async reset(key: string): Promise<void> {
		this.#entries.delete(key);
	}

	/**
	 * Keep the map under its bound: drop the expired windows, and if every
	 * window is still live, the oldest ones — a Map iterates in insertion
	 * order. Evicting a live window forgives its attempts; growing without
	 * bound would take the process down instead.
	 */
	#makeRoom(now: number): void {
		if (this.#entries.size < this.#maxKeys) return;
		for (const [key, entry] of this.#entries) {
			if (entry.resetAt <= now) this.#entries.delete(key);
		}
		for (const key of this.#entries.keys()) {
			if (this.#entries.size < this.#maxKeys) break;
			this.#entries.delete(key);
		}
	}
}

/** What {@link RedisAttemptStore} needs of a Redis client (ioredis, node-redis). */
export interface AttemptRedisClient {
	incr(key: string): Promise<number>;
	expire(key: string, seconds: number): Promise<unknown>;
	ttl(key: string): Promise<number>;
	get(key: string): Promise<string | null>;
	del(key: string): Promise<unknown>;
}

/** A client, or a resolver for one — resolved on the first attempt. */
export type AttemptRedisSource =
	| AttemptRedisClient
	| (() => Promise<AttemptRedisClient>);

/**
 * Shared across instances through Redis: `INCR`, then `EXPIRE` on the first
 * hit of a window.
 */
export class RedisAttemptStore implements AttemptStore {
	readonly #source: AttemptRedisSource;
	#resolved: AttemptRedisClient | undefined;
	readonly #prefix: string;

	constructor(source: AttemptRedisSource, options: { prefix?: string } = {}) {
		this.#source = source;
		this.#prefix = options.prefix ?? "warden:attempts";
	}

	async #client(): Promise<AttemptRedisClient> {
		if (this.#resolved) return this.#resolved;
		this.#resolved =
			typeof this.#source === "function" ? await this.#source() : this.#source;
		return this.#resolved;
	}

	async increment(key: string, windowSeconds: number): Promise<AttemptCount> {
		const client = await this.#client();
		const namespaced = `${this.#prefix}:${key}`;
		const count = await client.incr(namespaced);
		if (count === 1) {
			await client.expire(namespaced, windowSeconds);
			return { count, resetSeconds: windowSeconds };
		}
		const ttl = await client.ttl(namespaced);
		// A key with no expiry — the process died between its INCR and its
		// EXPIRE — would count forever: give it the window it should have had.
		if (ttl < 0) {
			await client.expire(namespaced, windowSeconds);
			return { count, resetSeconds: windowSeconds };
		}
		return { count, resetSeconds: ttl };
	}

	async count(key: string): Promise<number> {
		const client = await this.#client();
		const value = await client.get(`${this.#prefix}:${key}`);
		const count = Number(value ?? 0);
		return Number.isSafeInteger(count) ? count : 0;
	}

	async reset(key: string): Promise<void> {
		const client = await this.#client();
		await client.del(`${this.#prefix}:${key}`);
	}
}
