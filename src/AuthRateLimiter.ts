/**
 * AuthRateLimiter — brute force protection for login endpoints.
 *
 * Dual-key rate limiting: IP + email to prevent distributed attacks.
 *
 * @implements MISS-26
 */

export interface AuthRateLimiterConfig {
	maxAttempts?: number; // default 5
	windowSeconds?: number; // default 900 (15 min)
}

interface AttemptEntry {
	count: number;
	resetAt: number;
}

export class AuthRateLimiter {
	#maxAttempts: number;
	#window: number;
	#store: Map<string, AttemptEntry> = new Map();
	#maxStoreSize = 100_000;

	constructor(config?: AuthRateLimiterConfig) {
		this.#maxAttempts = config?.maxAttempts ?? 5;
		if (this.#maxAttempts <= 0) this.#maxAttempts = 1;
		this.#window = (config?.windowSeconds ?? 900) * 1000;
		if (this.#window <= 0) this.#window = 900_000; // prevent bypass via 0/negative
	}

	/** Check if an attempt is allowed. Returns false if rate limited. */
	check(ip: string, identifier: string): boolean {
		const now = Date.now();
		const ipNorm = normalizeIp(ip);
		const identifierNorm = normalizeIdentifier(identifier);
		// Dual key: limit both by IP and by identifier (email)
		const ipKey = `ip:${ipNorm}`;
		const idKey = `id:${identifierNorm}`;

		return this.#checkKey(ipKey, now) && this.#checkKey(idKey, now);
	}

	/** Record a failed attempt. */
	recordFailure(ip: string, identifier: string): void {
		const now = Date.now();
		const ipNorm = normalizeIp(ip);
		const identifierNorm = normalizeIdentifier(identifier);
		this.#increment(`ip:${ipNorm}`, now);
		this.#increment(`id:${identifierNorm}`, now);
	}

	/** Reset counters on successful login. */
	recordSuccess(ip: string, identifier: string): void {
		const ipNorm = normalizeIp(ip);
		const identifierNorm = normalizeIdentifier(identifier);
		this.#store.delete(`ip:${ipNorm}`);
		this.#store.delete(`id:${identifierNorm}`);
	}

	/** Get remaining attempts for an identifier. */
	remaining(ip: string, identifier: string): number {
		const ipNorm = normalizeIp(ip);
		const identifierNorm = normalizeIdentifier(identifier);
		const ipEntry = this.#store.get(`ip:${ipNorm}`);
		const idEntry = this.#store.get(`id:${identifierNorm}`);
		const ipRemaining = ipEntry
			? Math.max(0, this.#maxAttempts - ipEntry.count)
			: this.#maxAttempts;
		const idRemaining = idEntry
			? Math.max(0, this.#maxAttempts - idEntry.count)
			: this.#maxAttempts;
		return Math.min(ipRemaining, idRemaining);
	}

	#checkKey(key: string, now: number): boolean {
		const entry = this.#store.get(key);
		if (!entry || entry.resetAt < now) return true;
		return entry.count < this.#maxAttempts;
	}

	#increment(key: string, now: number): void {
		// Evict expired entries when store grows too large (prevent OOM)
		if (this.#store.size > this.#maxStoreSize) {
			for (const [k, v] of this.#store) {
				if (v.resetAt < now) this.#store.delete(k);
			}
		}

		let entry = this.#store.get(key);
		if (!entry || entry.resetAt < now) {
			entry = { count: 0, resetAt: now + this.#window };
			this.#store.set(key, entry);
		}
		entry.count++;
	}
}

function normalizeIdentifier(identifier: string): string {
	return identifier.trim().toLowerCase();
}

function normalizeIp(ip: string): string {
	return ip.trim();
}
