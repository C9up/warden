/**
 * OtpProvider — delivered one-time passcodes (email / SMS). Unlike TOTP this is
 * a challenge/response flow: `start()` mints a code, persists it (hashed, with
 * an expiry and an attempt budget) and hands it to a delivery channel; the user
 * later submits it to `verify()`.
 *
 * Delivery is pluggable — the app supplies an email or SMS channel. The store
 * is pluggable too, with an in-memory default mirroring the rest of warden.
 */

import {
	createHash,
	randomBytes,
	randomInt,
	timingSafeEqual,
} from "node:crypto";
import { WardenError } from "../errors.js";

/** Sends the code to the user. Implemented by the consuming app (email/SMS). */
export interface OtpDeliveryChannel {
	send(recipient: string, code: string): Promise<void>;
}

/** A persisted, pending OTP challenge. */
export interface OtpChallenge {
	id: string;
	recipient: string;
	/** Salted hash of the code — never the plaintext. */
	hash: string;
	expiresAt: number;
	attempts: number;
}

/** Storage for pending challenges. */
export interface OtpChallengeStore {
	save(challenge: OtpChallenge): Promise<void>;
	find(id: string): Promise<OtpChallenge | null>;
	delete(id: string): Promise<void>;
}

export class MemoryOtpChallengeStore implements OtpChallengeStore {
	#store = new Map<string, OtpChallenge>();
	async save(c: OtpChallenge): Promise<void> {
		this.#store.set(c.id, c);
	}
	async find(id: string): Promise<OtpChallenge | null> {
		return this.#store.get(id) ?? null;
	}
	async delete(id: string): Promise<void> {
		this.#store.delete(id);
	}
}

export interface OtpConfig {
	channel: OtpDeliveryChannel;
	/** Where pending challenges live. Default in-memory. */
	store?: OtpChallengeStore;
	/** Number of digits in the code. Default `6`. */
	digits?: number;
	/** How long a code stays valid, in seconds. Default `300` (5 min). */
	ttlSeconds?: number;
	/** Max verification attempts before the challenge is burned. Default `5`. */
	maxAttempts?: number;
}

export interface OtpStartResult {
	challengeId: string;
	expiresAt: number;
}

export type OtpFailureReason =
	| "not_found"
	| "expired"
	| "too_many_attempts"
	| "mismatch";

export interface OtpVerification {
	ok: boolean;
	reason?: OtpFailureReason;
}

export class OtpProvider {
	readonly kind = "otp" as const;
	readonly #channel: OtpDeliveryChannel;
	readonly #store: OtpChallengeStore;
	readonly #digits: number;
	readonly #ttlMs: number;
	readonly #maxAttempts: number;

	constructor(config: OtpConfig) {
		if (!config?.channel) {
			throw new WardenError(
				"INVALID_CONFIG",
				"OtpProvider requires a delivery channel (email/SMS)",
			);
		}
		this.#channel = config.channel;
		this.#store = config.store ?? new MemoryOtpChallengeStore();

		// Validate the numeric config up-front (mirrors TotpProvider's digit
		// guard) so a misconfig fails loudly at construction instead of minting
		// unusable codes: `digits` bounds the code length (also keeps `10**digits`
		// within `randomInt`'s safe range); a non-positive `ttlSeconds` would make
		// every code born-expired; a non-positive `maxAttempts` would burn the
		// challenge on the first guess.
		const digits = config.digits ?? 6;
		if (!Number.isInteger(digits) || digits < 4 || digits > 10) {
			throw new WardenError(
				"INVALID_CONFIG",
				`OTP digits must be an integer 4-10, got ${digits}`,
			);
		}
		const ttlSeconds = config.ttlSeconds ?? 300;
		if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
			throw new WardenError(
				"INVALID_CONFIG",
				`OTP ttlSeconds must be a positive integer, got ${ttlSeconds}`,
			);
		}
		const maxAttempts = config.maxAttempts ?? 5;
		if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
			throw new WardenError(
				"INVALID_CONFIG",
				`OTP maxAttempts must be a positive integer, got ${maxAttempts}`,
			);
		}
		this.#digits = digits;
		this.#ttlMs = ttlSeconds * 1000;
		this.#maxAttempts = maxAttempts;
	}

	/** Mint a code, persist the challenge, and deliver it to `recipient`. */
	async start(
		recipient: string,
		nowMs: number = Date.now(),
	): Promise<OtpStartResult> {
		const code = this.#randomCode();
		const id = randomBytes(16).toString("hex");
		const expiresAt = nowMs + this.#ttlMs;
		await this.#store.save({
			id,
			recipient,
			hash: saltedHash(code),
			expiresAt,
			attempts: 0,
		});
		await this.#channel.send(recipient, code);
		return { challengeId: id, expiresAt };
	}

	/**
	 * Verify a submitted code. Wrong codes consume an attempt; the challenge is
	 * deleted on success, on expiry, or once the attempt budget is exhausted.
	 */
	async verify(
		challengeId: string,
		code: string,
		nowMs: number = Date.now(),
	): Promise<OtpVerification> {
		const challenge = await this.#store.find(challengeId);
		if (!challenge) {
			return { ok: false, reason: "not_found" };
		}
		if (nowMs > challenge.expiresAt) {
			await this.#store.delete(challengeId);
			return { ok: false, reason: "expired" };
		}
		if (matchesStored(challenge.hash, code.replace(/\s/g, ""))) {
			await this.#store.delete(challengeId);
			return { ok: true };
		}
		const attempts = challenge.attempts + 1;
		if (attempts >= this.#maxAttempts) {
			await this.#store.delete(challengeId);
			return { ok: false, reason: "too_many_attempts" };
		}
		await this.#store.save({ ...challenge, attempts });
		return { ok: false, reason: "mismatch" };
	}

	#randomCode(): string {
		const max = 10 ** this.#digits;
		return randomInt(0, max).toString().padStart(this.#digits, "0");
	}
}

function saltedHash(code: string): string {
	const salt = randomBytes(8);
	const digest = createHash("sha256").update(salt).update(code).digest();
	return `${salt.toString("hex")}$${digest.toString("hex")}`;
}

function matchesStored(stored: string, candidate: string): boolean {
	const sep = stored.indexOf("$");
	if (sep === -1) {
		return false;
	}
	const salt = Buffer.from(stored.slice(0, sep), "hex");
	const expected = Buffer.from(stored.slice(sep + 1), "hex");
	const actual = createHash("sha256").update(salt).update(candidate).digest();
	if (actual.length !== expected.length) {
		return false;
	}
	return timingSafeEqual(actual, expected);
}
