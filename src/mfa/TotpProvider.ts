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
	readonly #cfg: Required<TotpConfig>;

	constructor(config: TotpConfig = {}) {
		this.#cfg = { ...DEFAULTS, ...config };
		if (this.#cfg.digits < 6 || this.#cfg.digits > 8) {
			throw new WardenError(
				"INVALID_CONFIG",
				`TOTP digits must be 6-8, got ${this.#cfg.digits}`,
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
	verify(secret: string, code: string, atMs: number = Date.now()): boolean {
		const normalized = code.replace(/\s/g, "");
		if (normalized.length !== this.#cfg.digits) {
			return false;
		}
		const key = base32Decode(secret);
		const current = Math.floor(atMs / 1000 / this.#cfg.period);
		for (let offset = -this.#cfg.window; offset <= this.#cfg.window; offset++) {
			if (constantTimeEqual(this.#hotp(key, current + offset), normalized)) {
				return true;
			}
		}
		return false;
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
		const off = hmac[hmac.length - 1] & 0xf;
		const bin =
			((hmac[off] & 0x7f) << 24) |
			((hmac[off + 1] & 0xff) << 16) |
			((hmac[off + 2] & 0xff) << 8) |
			(hmac[off + 3] & 0xff);
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
