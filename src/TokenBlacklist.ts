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

/** In-memory blacklist for development. */
export class MemoryBlacklistDriver implements BlacklistDriver {
	#entries: Map<string, number> = new Map();

	async add(jti: string, expiresAt: number): Promise<void> {
		this.#entries.set(jti, expiresAt);
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
		const now = Date.now();
		for (const [jti, exp] of this.#entries) {
			if (exp < now) this.#entries.delete(jti);
		}
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
