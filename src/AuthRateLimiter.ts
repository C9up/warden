/**
 * AuthRateLimiter — brute force protection for login endpoints, and the
 * lockout behind `MfaManager.verify()`.
 *
 * An attempt is counted BEFORE the credential is checked, by one atomic
 * increment per key ({@link AttemptStore}): checking first and recording the
 * failure afterwards let a burst of concurrent attempts all pass the check.
 * A success clears the keys.
 *
 * A login is counted under two keys, its IP and its identifier
 * ({@link AuthRateLimiter.loginKeys}), so neither spraying one password across
 * accounts from one address nor one account from many addresses gets through.
 *
 *   const keys = AuthRateLimiter.loginKeys(ctx.request.ip(), email)
 *   if (!(await limiter.attempt(...keys)).allowed) return tooManyAttempts()
 *   const user = await verify(email, password)
 *   if (user) await limiter.clear(...keys)
 *
 * @implements MISS-26
 */

import { type AttemptStore, MemoryAttemptStore } from "./AttemptStore.js";
import { WardenError } from "./errors.js";

export interface AuthRateLimiterConfig {
	/** Attempts allowed per window, per key. Default 5. */
	maxAttempts?: number;
	/** How long a window lasts, in seconds. Default 900 (15 min). */
	windowSeconds?: number;
	/**
	 * Where the counts live. Default: this process's memory. A cluster passes a
	 * shared one ({@link RedisAttemptStore}), or a lockout holds only on the
	 * instance that counted it.
	 */
	store?: AttemptStore;
}

/** What {@link AuthRateLimiter.attempt} decided. */
export interface AttemptDecision {
	/** Whether this attempt may go on to the credential check. */
	allowed: boolean;
	/** Attempts left on the most-used key. */
	remaining: number;
	/** Seconds until the most-used key's window ends. */
	retryAfterSeconds: number;
}

export class AuthRateLimiter {
	readonly #maxAttempts: number;
	readonly #windowSeconds: number;
	readonly #store: AttemptStore;

	constructor(config: AuthRateLimiterConfig = {}) {
		this.#maxAttempts = positiveInteger("maxAttempts", config.maxAttempts ?? 5);
		this.#windowSeconds = positiveInteger(
			"windowSeconds",
			config.windowSeconds ?? 900,
		);
		this.#store = config.store ?? new MemoryAttemptStore();
	}

	/** The keys a login attempt is counted under: its IP and its identifier. */
	static loginKeys(ip: string, identifier: string): string[] {
		return [`ip:${ip.trim()}`, `id:${identifier.trim().toLowerCase()}`];
	}

	/**
	 * Count an attempt under every key, and say whether it may go on. Call it
	 * BEFORE checking the credential; a refused attempt must not reach it.
	 */
	async attempt(...keys: string[]): Promise<AttemptDecision> {
		const counts = await Promise.all(
			keys.map((key) => this.#store.increment(key, this.#windowSeconds)),
		);
		let highest = { count: 0, resetSeconds: 0 };
		for (const counted of counts) {
			if (counted.count > highest.count) highest = counted;
		}
		return {
			allowed: highest.count <= this.#maxAttempts,
			remaining: Math.max(0, this.#maxAttempts - highest.count),
			retryAfterSeconds: highest.resetSeconds,
		};
	}

	/** Whether any key has used up its attempts, without counting one. */
	async isBlocked(...keys: string[]): Promise<boolean> {
		const counts = await Promise.all(keys.map((key) => this.#store.count(key)));
		return counts.some((count) => count >= this.#maxAttempts);
	}

	/** Forget the keys' attempts — after a success. */
	async clear(...keys: string[]): Promise<void> {
		await Promise.all(keys.map((key) => this.#store.reset(key)));
	}
}

/**
 * A limit that would not limit is refused: `Infinity` attempts or a window of
 * 0 turned the protection off, silently.
 */
function positiveInteger(field: string, value: number): number {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new WardenError(
			"INVALID_CONFIG",
			`AuthRateLimiter ${field} must be a positive whole number, got ${String(value)}`,
		);
	}
	return value;
}
