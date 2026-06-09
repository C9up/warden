/**
 * ResilientBlacklistDriver — wraps a primary blacklist (e.g. KeyDB-backed
 * `RedisBlacklistDriver`) with an in-memory fallback so a cache outage never
 * takes the whole app down.
 *
 * Policy (fail-open on reads):
 *   - `add()`  — if the primary throws, the revocation is recorded in the
 *                fallback so logout stays effective on this instance.
 *   - `has()`  — if the primary throws, consult the fallback: a token revoked
 *                during the outage is still caught here; anything else is
 *                allowed through (fail-open). Access tokens are short-lived, so
 *                the window a missed revocation survives is bounded by the token
 *                TTL — the blacklist is defense-in-depth above expiry, not the
 *                primary boundary.
 *
 * Every degradation invokes `onDegrade` (defaults to a stderr warning) so the
 * outage is observable.
 */

import {
	type BlacklistDriver,
	MemoryBlacklistDriver,
} from "./TokenBlacklist.js";

export interface BlacklistDegradeEvent {
	op: "add" | "has" | "cleanup";
	error: unknown;
}

export interface ResilientBlacklistConfig {
	/** Invoked whenever the primary driver fails and the fallback is used. */
	onDegrade?: (event: BlacklistDegradeEvent) => void;
}

function defaultOnDegrade({ op, error }: BlacklistDegradeEvent): void {
	console.warn(
		`[warden] blacklist primary failed on ${op}; using in-memory fallback:`,
		error,
	);
}

export class ResilientBlacklistDriver implements BlacklistDriver {
	readonly #primary: BlacklistDriver;
	readonly #fallback: BlacklistDriver;
	readonly #onDegrade: (event: BlacklistDegradeEvent) => void;

	constructor(
		primary: BlacklistDriver,
		fallback: BlacklistDriver = new MemoryBlacklistDriver(),
		config: ResilientBlacklistConfig = {},
	) {
		this.#primary = primary;
		this.#fallback = fallback;
		this.#onDegrade = config.onDegrade ?? defaultOnDegrade;
	}

	async add(jti: string, expiresAt: number): Promise<void> {
		try {
			await this.#primary.add(jti, expiresAt);
		} catch (error) {
			this.#onDegrade({ op: "add", error });
			await this.#fallback.add(jti, expiresAt);
		}
	}

	async has(jti: string): Promise<boolean> {
		try {
			return await this.#primary.has(jti);
		} catch (error) {
			this.#onDegrade({ op: "has", error });
			// Fail-open: honour in-outage revocations on this instance, allow rest.
			return this.#fallback.has(jti);
		}
	}

	async cleanup(): Promise<void> {
		try {
			await this.#primary.cleanup();
		} catch (error) {
			this.#onDegrade({ op: "cleanup", error });
		}
		await this.#fallback.cleanup();
	}
}
