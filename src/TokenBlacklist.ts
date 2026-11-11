/**
 * TokenBlacklist — revoke JWT tokens before expiry.
 *
 * Stores JTI (JWT ID) with expiry. Supports Memory and Redis drivers.
 *
 * @implements MISS-6
 */

export interface BlacklistDriver {
	add(jti: string, expiresAt: number): Promise<void>;
	has(jti: string): Promise<boolean>;
	/**
	 * Reap expired entries. Optional: TTL-backed stores (Redis/KeyDB) expire keys
	 * themselves and have nothing to sweep, so they may omit this.
	 */
	cleanup?(): Promise<void>;
}

/** In-memory blacklist for development, and the resilient driver's fallback. */
export class MemoryBlacklistDriver implements BlacklistDriver {
	#entries: Map<string, number> = new Map();

	/**
	 * Size at which the next sweep runs, doubling each time.
	 *
	 * Expired entries used to leave only on a `has()` of that exact jti or an
	 * explicit `cleanup()`, which nothing calls. Every logout and every
	 * `revoke()` added one, and `ResilientBlacklistDriver` writes every
	 * revocation into this store, so a long-lived process grew without bound.
	 * Sweeping on write bounds the map by the revocations still live, without
	 * a timer that would hold the event loop open. There is no ceiling that
	 * evicts: dropping a live entry would un-revoke a token.
	 */
	#sweepAt = 64;

	/** Entries currently held, live or not yet swept. */
	get size(): number {
		return this.#entries.size;
	}

	async add(jti: string, expiresAt: number): Promise<void> {
		// Already past its deadline: `has()` would answer false for it anyway,
		// so storing it only costs memory.
		if (expiresAt < Date.now()) return;
		this.#entries.set(jti, expiresAt);
		if (this.#entries.size > this.#sweepAt) this.#sweep();
	}

	async has(jti: string): Promise<boolean> {
		const expiresAt = this.#entries.get(jti);
		if (expiresAt === undefined) return false;
		if (expiresAt < Date.now()) {
			this.#entries.delete(jti);
			return false;
		}
		return true;
	}

	async cleanup(): Promise<void> {
		this.#sweep();
	}

	#sweep(): void {
		const now = Date.now();
		for (const [jti, exp] of this.#entries) {
			if (exp < now) this.#entries.delete(jti);
		}
		this.#sweepAt = Math.max(64, this.#entries.size * 2);
	}
}

export class TokenBlacklist {
	constructor(private driver: BlacklistDriver) {}

	/** Revoke a token by its JTI claim. */
	async revoke(jti: string, expiresAt: number): Promise<void> {
		await this.driver.add(jti, expiresAt);
	}

	/** Check if a token JTI is blacklisted. */
	async isRevoked(jti: string): Promise<boolean> {
		return this.driver.has(jti);
	}

	/** Remove expired entries (no-op when the driver self-expires via TTL). */
	async cleanup(): Promise<void> {
		await this.driver.cleanup?.();
	}
}
