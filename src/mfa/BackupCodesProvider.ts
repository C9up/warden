/**
 * BackupCodesProvider — single-use recovery codes for when a user loses their
 * authenticator. Codes are shown to the user exactly once at generation time;
 * only salted hashes are persisted. Verifying a code consumes it.
 *
 * Codes are high-entropy random tokens (default ~50 bits), so a single salted
 * SHA-256 is the right primitive here — not an expensive password KDF.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { WardenError } from "../errors.js";
import { base32Encode } from "./base32.js";

export interface BackupCodesConfig {
	/** How many codes to generate. Default `10`. */
	count?: number;
	/** Characters per code (base32, excludes the separator). Default `10`. */
	length?: number;
}

export interface BackupCodesResult {
	/** Plaintext codes — display ONCE, never persist. */
	codes: string[];
	/** Salted hashes (`salt$digest`) to persist against the user. */
	hashes: string[];
}

export interface BackupCodeVerification {
	ok: boolean;
	/** The hash list with the consumed code removed (persist this on success). */
	remaining: string[];
}

const DEFAULTS = { count: 10, length: 10 };

export class BackupCodesProvider {
	readonly kind = "backup_codes" as const;
	readonly #cfg: Required<BackupCodesConfig>;

	constructor(config: BackupCodesConfig = {}) {
		this.#cfg = { ...DEFAULTS, ...config };
		if (this.#cfg.count < 1) {
			throw new WardenError(
				"INVALID_CONFIG",
				`backup code count must be >= 1, got ${this.#cfg.count}`,
			);
		}
		if (this.#cfg.length < 8) {
			throw new WardenError(
				"INVALID_CONFIG",
				`backup code length must be >= 8 for adequate entropy, got ${this.#cfg.length}`,
			);
		}
	}

	/** Generate a fresh batch of codes plus the hashes to persist. */
	generate(): BackupCodesResult {
		const codes: string[] = [];
		const hashes: string[] = [];
		for (let i = 0; i < this.#cfg.count; i++) {
			const raw = base32Encode(randomBytes(this.#cfg.length)).slice(
				0,
				this.#cfg.length,
			);
			// Split in the middle for readability: "ABCDE-FGHIJ".
			const half = Math.floor(this.#cfg.length / 2);
			codes.push(`${raw.slice(0, half)}-${raw.slice(half)}`);
			hashes.push(saltedHash(raw));
		}
		return { codes, hashes };
	}

	/**
	 * Verify a user-supplied code against the stored hashes. On a match the
	 * code is consumed: `remaining` excludes it and must be persisted. Input is
	 * normalized (separators stripped, upper-cased) before comparison.
	 */
	verify(hashes: string[], code: string): BackupCodeVerification {
		const candidate = normalize(code);
		let matchedIndex = -1;
		// Scan every entry (no early exit) so timing doesn't leak position.
		for (const [i, stored] of hashes.entries()) {
			if (matchesStored(stored, candidate)) {
				matchedIndex = i;
			}
		}
		if (matchedIndex === -1) {
			return { ok: false, remaining: hashes };
		}
		return {
			ok: true,
			remaining: hashes.filter((_, i) => i !== matchedIndex),
		};
	}
}

function normalize(code: string): string {
	return code.replace(/[\s-]/g, "").toUpperCase();
}

/** Hash a normalized code under a fresh random salt → `salt$digest` (hex). */
function saltedHash(normalized: string): string {
	const salt = randomBytes(8);
	const digest = digestWith(salt, normalized);
	return `${salt.toString("hex")}$${digest.toString("hex")}`;
}

/** Re-hash the candidate under the stored entry's salt and compare. */
function matchesStored(stored: string, candidate: string): boolean {
	const sep = stored.indexOf("$");
	if (sep === -1) {
		return false;
	}
	const salt = Buffer.from(stored.slice(0, sep), "hex");
	const expected = Buffer.from(stored.slice(sep + 1), "hex");
	const actual = digestWith(salt, candidate);
	if (actual.length !== expected.length) {
		return false;
	}
	return timingSafeEqual(actual, expected);
}

function digestWith(salt: Buffer, normalized: string): Buffer {
	return createHash("sha256").update(salt).update(normalized).digest();
}
