/**
 * ResilientBlacklistDriver — wraps a primary blacklist (e.g. KeyDB-backed
 * `RedisBlacklistDriver`) with an in-memory fallback so a cache outage never
 * takes the whole app down.
 *
 * Policy (fail-open on reads):
 *   - `add()`  — records the revocation in BOTH, always. The fallback is this
 *                instance's own record of what it has revoked, not a log of its
 *                outages: writing only on failure meant a token revoked while
 *                the primary was HEALTHY was absent from the fallback, so the
 *                first check during a later outage let that logged-out token
 *                through. A primary failure still does not fail the logout.
 *   - `has()`  — asks the fallback FIRST: what this instance revoked is known
 *                locally and needs no round trip. Otherwise it asks the
 *                primary, and if that throws, allows the token through
 *                (fail-open). Access tokens are short-lived, so the window a
 *                revocation missed by BOTH survives is bounded by the token TTL
 *                — the blacklist is defense-in-depth above expiry, not the
 *                primary boundary.
 *
 * Every degradation invokes `onDegrade`. The default reports the first failure
 * per operation and then a periodic count: an outage that logs on every request
 * buries itself, and the reader stops seeing what the flood is about.
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

/** How long a repeat of the same failing operation stays folded into a count. */
const DEGRADE_LOG_WINDOW_MS = 60_000;

/**
 * Report the first failure of each operation, then one line per window with
 * how many were suppressed.
 *
 * Keyed by operation — a fixed, three-value set — never by the error text,
 * which an attacker could influence and which would make the key set unbounded.
 */
function makeDefaultOnDegrade(): (event: BlacklistDegradeEvent) => void {
	const windows = new Map<string, { until: number; suppressed: number }>();
	return ({ op, error }: BlacklistDegradeEvent): void => {
		const now = Date.now();
		const open = windows.get(op);
		if (open === undefined || open.until <= now) {
			if (open !== undefined && open.suppressed > 0) {
				console.warn(
					`[warden] blacklist primary failed on ${op} ${open.suppressed} more time(s) in the last minute.`,
				);
			}
			windows.set(op, { until: now + DEGRADE_LOG_WINDOW_MS, suppressed: 0 });
			console.warn(
				`[warden] blacklist primary failed on ${op}; using in-memory fallback:`,
				error,
			);
			return;
		}
		open.suppressed++;
	};
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
		this.#onDegrade = config.onDegrade ?? makeDefaultOnDegrade();
	}

	async add(jti: string, expiresAt: number): Promise<void> {
		// The fallback first, and unconditionally: it is what this instance
		// knows it revoked. Recording only on failure left every revocation made
		// while the primary was healthy invisible to the fallback — and those are
		// most of them.
		await this.#fallback.add(jti, expiresAt);
		try {
			await this.#primary.add(jti, expiresAt);
		} catch (error) {
			// The revocation is already durable enough for this instance, so a
			// primary failure must not fail the logout.
			this.#onDegrade({ op: "add", error });
		}
	}

	async has(jti: string): Promise<boolean> {
		// What this instance revoked is known locally — no round trip needed, and
		// it stays correct through an outage that starts a moment later.
		if (await this.#fallback.has(jti)) return true;
		try {
			return await this.#primary.has(jti);
		} catch (error) {
			this.#onDegrade({ op: "has", error });
			// Fail-open on what neither knows: access tokens are short-lived.
			return false;
		}
	}

	async cleanup(): Promise<void> {
		try {
			await this.#primary.cleanup?.();
		} catch (error) {
			this.#onDegrade({ op: "cleanup", error });
		}
		await this.#fallback.cleanup?.();
	}
}
