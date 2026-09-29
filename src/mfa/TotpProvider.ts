/**
 * TotpProvider — RFC 6238 time-based one-time passwords (HOTP/RFC 4226 under
 * the hood). Pure TypeScript on Node's `crypto.createHmac` — no native binding
 * and no third-party dependency: a TOTP is a single HMAC, not CPU-bound work.
 *
 * Compatible with Google Authenticator / 1Password / Authy by default
 * (SHA1, 6 digits, 30s period).
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { WardenError } from "../errors.js";
import { base32Decode, base32Encode } from "./base32.js";

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

const TOTP_ALGORITHMS: readonly string[] = ["SHA1", "SHA256", "SHA512"];

/** Throw INVALID_CONFIG unless `value` is an integer in `[min, max]`. */
export function assertIntegerIn(
	what: string,
	value: number,
	min: number,
	max: number,
): void {
	if (!Number.isInteger(value) || value < min || value > max) {
		throw new WardenError(
			"INVALID_CONFIG",
			`${what} must be a whole number from ${min} to ${max}, got ${String(value)}`,
		);
	}
}

export interface TotpConfig {
	/** HMAC algorithm. Default `SHA1` (authenticator-app compatible). */
	algorithm?: TotpAlgorithm;
	/** Number of digits in the generated code. Default `6`. */
	digits?: number;
	/** Time step in seconds. Default `30`. */
	period?: number;
	/**
	 * How many time steps before/after `now` are accepted on `verify`, to
	 * tolerate clock skew. Default `1` (i.e. ±30s with the default period).
	 */
	window?: number;
	/**
	 * Remembers codes already accepted, so one cannot be used twice
	 * (RFC 6238 §5.2). Defaults to an in-process guard, which is correct for a
	 * single instance; inject a shared store (Redis, the session table) when the
	 * app runs on several.
	 *
	 * Omit deliberately — `replayGuard: null` — to accept replays, e.g. when an
	 * outer layer already enforces single use.
	 */
	replayGuard?: TotpReplayGuard | null;
}

/**
 * Remembers accepted (secret, time-step) pairs for as long as they could still
 * be replayed.
 *
 * Keys are opaque digests, never the secret itself: a store may be shared, and
 * a guard that leaks the seed is worse than the replay it prevents.
 *
 * One operation, not a "was it used?" read followed by a "remember it" write:
 * between the two, a second request with the same code read "unused" too, and
 * both were accepted.
 */
export interface TotpReplayGuard {
	/**
	 * Record `key` as used for `ttlMs` — ATOMICALLY, only if it is not already
	 * recorded (Redis `SET key 1 PX ttl NX`). True when this call recorded it:
	 * the code is accepted. False when it was already used.
	 */
	claim(key: string, ttlMs: number): boolean | Promise<boolean>;
}

/**
 * In-process replay guard. Entries expire on their own, and a sweep runs
 * whenever one is added, so the set stays bounded by the accept window rather
 * than by how many codes have been tried.
 */
export class MemoryTotpReplayGuard implements TotpReplayGuard {
	readonly #seen = new Map<string, number>();

	/** Synchronous: nothing can run between the check and the write. */
	claim(key: string, ttlMs: number): boolean {
		const now = Date.now();
		for (const [seenKey, expiresAt] of this.#seen) {
			if (expiresAt <= now) this.#seen.delete(seenKey);
		}
		if (this.#seen.has(key)) return false;
		this.#seen.set(key, now + ttlMs);
		return true;
	}
}

/** What {@link RedisTotpReplayGuard} needs of a Redis client. */
export interface ReplayRedisClient {
	set(
		key: string,
		value: string,
		expiry: "PX",
		ttlMs: number,
		mode: "NX",
	): Promise<unknown>;
}

/**
 * A replay guard shared across instances: `SET key 1 PX ttl NX` records a code
 * only if no instance did first. Needed as soon as the app runs on more than
 * one, or the same code works once per instance.
 */
export class RedisTotpReplayGuard implements TotpReplayGuard {
	readonly #source: ReplayRedisClient | (() => Promise<ReplayRedisClient>);
	#resolved: ReplayRedisClient | undefined;
	readonly #prefix: string;

	constructor(
		source: ReplayRedisClient | (() => Promise<ReplayRedisClient>),
		options: { prefix?: string } = {},
	) {
		this.#source = source;
		this.#prefix = options.prefix ?? "warden:totp";
	}

	async claim(key: string, ttlMs: number): Promise<boolean> {
		if (this.#resolved === undefined) {
			this.#resolved =
				typeof this.#source === "function"
					? await this.#source()
					: this.#source;
		}
		// Redis refuses PX 0; a code with no replay time left still gets 1 ms.
		const result = await this.#resolved.set(
			`${this.#prefix}:${key}`,
			"1",
			"PX",
			Math.max(1, Math.ceil(ttlMs)),
			"NX",
		);
		return result === "OK";
	}
}

export interface TotpEnrollment {
	/** Base32 secret to persist against the user. */
	secret: string;
	/** `otpauth://` URI to render as a QR code during enrollment. */
	uri: string;
}

const DEFAULTS = {
	algorithm: "SHA1" as TotpAlgorithm,
	digits: 6,
	period: 30,
	window: 1,
};

export class TotpProvider {
	readonly kind = "totp" as const;
	readonly #cfg: Required<Omit<TotpConfig, "replayGuard">>;
	readonly #replayGuard: TotpReplayGuard | null;

	constructor(config: TotpConfig = {}) {
		const { replayGuard, ...rest } = config;
		this.#cfg = { ...DEFAULTS, ...rest };
		// Defaults ON: a code that works twice is the failure this exists to
		// prevent, so opting out has to be deliberate.
		this.#replayGuard =
			replayGuard === null
				? null
				: (replayGuard ?? new MemoryTotpReplayGuard());
		// Every number bounds a loop or a buffer: a period of 0 crashed code
		// generation, a window of Infinity never ended the verification loop,
		// and NaN slips past a `<` comparison.
		assertIntegerIn("TOTP digits", this.#cfg.digits, 6, 8);
		assertIntegerIn("TOTP period", this.#cfg.period, 1, 3600);
		assertIntegerIn("TOTP window", this.#cfg.window, 0, 10);
		if (!TOTP_ALGORITHMS.includes(this.#cfg.algorithm)) {
			throw new WardenError(
				"INVALID_CONFIG",
				`TOTP algorithm must be one of ${TOTP_ALGORITHMS.join(", ")}, got ${String(this.#cfg.algorithm)}`,
			);
		}
	}

	/**
	 * Generate a fresh secret and the `otpauth://` provisioning URI. Persist
	 * `secret`; render `uri` as a QR code for the user to scan.
	 *
	 * @param account  Identifies the account in the authenticator (usually the
	 *                 user's email or username).
	 * @param issuer   Your app/brand name, shown as the entry label.
	 */
	enroll(account: string, issuer: string): TotpEnrollment {
		const secret = base32Encode(randomBytes(20));
		return { secret, uri: this.uri(secret, account, issuer) };
	}

	/** Build the `otpauth://totp/...` provisioning URI for an existing secret. */
	uri(secret: string, account: string, issuer: string): string {
		const label = encodeURIComponent(`${issuer}:${account}`);
		const params = new URLSearchParams({
			secret,
			issuer,
			algorithm: this.#cfg.algorithm,
			digits: String(this.#cfg.digits),
			period: String(this.#cfg.period),
		});
		return `otpauth://totp/${label}?${params.toString()}`;
	}

	/** Generate the code for a given secret at a given time (ms since epoch). */
	generate(secret: string, atMs: number = Date.now()): string {
		const counter = Math.floor(atMs / 1000 / this.#cfg.period);
		return this.#hotp(base32Decode(secret), counter);
	}

	/**
	 * Verify a user-supplied code against the secret, accepting codes from the
	 * surrounding `window` time steps to tolerate clock skew. Constant-time.
	 */
	async verify(
		secret: string,
		code: string,
		atMs: number = Date.now(),
	): Promise<boolean> {
		const normalized = code.replace(/\s/g, "");
		if (normalized.length !== this.#cfg.digits) {
			return false;
		}
		const key = base32Decode(secret);
		const current = Math.floor(atMs / 1000 / this.#cfg.period);
		for (let offset = -this.#cfg.window; offset <= this.#cfg.window; offset++) {
			const counter = current + offset;
			if (!constantTimeEqual(this.#hotp(key, counter), normalized)) continue;
			if (this.#replayGuard === null) return true;
			// A matching code is only accepted ONCE. Without this it stays valid
			// for the whole window — with the default settings, ~90 seconds in
			// which a shoulder-surfed or intercepted code still works.
			const seenKey = this.#replayKey(secret, counter);
			// Claimed for as long as it could still be replayed: until the last
			// step that would accept it has passed.
			const ttlMs =
				(counter + this.#cfg.window + 1) * this.#cfg.period * 1000 - atMs;
			return this.#replayGuard.claim(seenKey, Math.max(ttlMs, 0));
		}
		return false;
	}

	/**
	 * An opaque key for one (secret, step) pair. Hashed, so a shared store never
	 * holds the seed, and bounded in length whatever the secret looks like.
	 */
	#replayKey(secret: string, counter: number): string {
		return createHmac("sha256", secret)
			.update(`totp:${counter}`)
			.digest("base64url");
	}

	/** RFC 4226 HOTP: HMAC over the 8-byte counter, dynamically truncated. */
	#hotp(key: Uint8Array, counter: number): string {
		const buf = Buffer.alloc(8);
		// 64-bit big-endian counter. Codes stay valid well past year 2^53,
		// so splitting hi/lo at 2^32 is safe and avoids BigInt overhead.
		buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
		buf.writeUInt32BE(counter >>> 0, 4);

		const hmac = createHmac(this.#cfg.algorithm.toLowerCase(), Buffer.from(key))
			.update(buf)
			.digest();
		// RFC 4226 dynamic truncation. `readUInt32BE` reads the four bytes as
		// one value and bounds-checks itself, where four indexed reads each
		// came back "a byte, or nothing" — the digest is 20 bytes and the
		// offset is masked to 0-15, so the window always fits.
		const off = (hmac.at(-1) ?? 0) & 0xf;
		const bin = hmac.readUInt32BE(off) & 0x7fffffff;
		return (bin % 10 ** this.#cfg.digits)
			.toString()
			.padStart(this.#cfg.digits, "0");
	}
}

/** Length-safe constant-time string compare (avoids early-exit timing leaks). */
function constantTimeEqual(a: string, b: string): boolean {
	const ba = Buffer.from(a);
	const bb = Buffer.from(b);
	if (ba.length !== bb.length) {
		return false;
	}
	return timingSafeEqual(ba, bb);
}
