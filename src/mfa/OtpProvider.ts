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

/**
 * Storage for pending challenges.
 *
 * {@link take} is what makes a one-time code one-time. Verification used to be
 * `find` then compare then `delete` — three operations with `await` between
 * them — so two requests carrying the same correct code both read the challenge
 * before either removed it, and both were told `ok`. The attempt budget had the
 * same shape: concurrent wrong guesses each read `attempts: 0` and wrote `1`,
 * so twenty of them burned one attempt. A store backed by a network widens that
 * window from microseconds to a round trip.
 *
 * A custom store MUST implement `take` as a single indivisible operation:
 * `DELETE ... RETURNING` on SQL, `GETDEL` or a Lua script on Redis, a
 * compare-and-set on anything else. Handing back a copy and deleting separately
 * reopens the hole this exists to close.
 */
export interface OtpChallengeStore {
	save(challenge: OtpChallenge): Promise<void>;
	find(id: string): Promise<OtpChallenge | null>;
	delete(id: string): Promise<void>;
	/**
	 * Atomically remove the challenge and return what was removed.
	 *
	 * At most one concurrent caller can be handed a given challenge; every
	 * other gets `null`. Whoever holds it decides what happens next — spend it,
	 * or put it back with one more attempt recorded.
	 */
	take(id: string): Promise<OtpChallenge | null>;
}

export class MemoryOtpChallengeStore implements OtpChallengeStore {
	#store = new Map<string, OtpChallenge>();
	/**
	 * Size at which the next sweep runs, doubling each time.
	 *
	 * Entries only ever left when their id was reused or taken, so a challenge
	 * nobody came back for — a code requested and never submitted, which is the
	 * ordinary abandoned login — stayed for the life of the process. Sweeping on
	 * write keeps it bounded without a timer: a timer would hold the event loop
	 * open and need a disposal contract this store does not have.
	 *
	 * Doubling makes the cost amortised O(1) per save rather than a scan on
	 * every one, and the floor keeps a small deployment from sweeping constantly.
	 */
	#sweepAt = 64;
	readonly #maxEntries: number;

	/**
	 * @param maxEntries How many pending challenges this process will hold.
	 *   Sweeping only removes EXPIRED entries, so a flood of still-valid ones —
	 *   an unauthenticated endpoint being hammered — grew the map without any
	 *   ceiling. Default 10 000, which is far above a real login rate and far
	 *   below a memory problem.
	 */
	constructor(maxEntries = 10_000) {
		// A ceiling of 0, a negative, NaN or Infinity is not a ceiling: the
		// first two refuse every write and the last two disable the bound this
		// exists to provide, silently. A caller asking for one of those means
		// something, and none of the meanings is what would have happened.
		if (!Number.isInteger(maxEntries) || maxEntries < 1) {
			throw new WardenError(
				"E_WARDEN_STORE_LIMIT_INVALID",
				`maxEntries must be a positive integer, got ${String(maxEntries)}.`,
				{
					hint: "Pass the number of pending entries this process may hold — the default is 10_000.",
				},
			);
		}
		this.#maxEntries = maxEntries;
	}

	async save(c: OtpChallenge): Promise<void> {
		if (this.#store.size >= this.#maxEntries && !this.#store.has(c.id)) {
			// Swept first: the ceiling is about live challenges, not stale ones.
			this.#sweep();
		}
		if (this.#store.size >= this.#maxEntries && !this.#store.has(c.id)) {
			// REFUSED, not evicted. Evicting to make room lets whoever is
			// flooding push a legitimate user's challenge out and lock them out;
			// refusing the new one fails the attacker instead.
			throw new WardenError(
				"E_WARDEN_OTP_STORE_FULL",
				`The in-memory OTP store is full (${this.#maxEntries} pending challenges).`,
				{
					hint: "Rate-limit the endpoint that mints codes, or move to a persistent store with its own TTL.",
				},
			);
		}
		this.#store.set(c.id, c);
		if (this.#store.size > this.#sweepAt) this.#sweep();
	}

	/** Drop everything already expired. */
	#sweep(): void {
		const now = Date.now();
		for (const [id, challenge] of this.#store) {
			if (challenge.expiresAt < now) this.#store.delete(id);
		}
		this.#sweepAt = Math.max(64, this.#store.size * 2);
	}
	async find(id: string): Promise<OtpChallenge | null> {
		return this.#store.get(id) ?? null;
	}
	async delete(id: string): Promise<void> {
		this.#store.delete(id);
	}
	/**
	 * Atomic here for free: a synchronous read-and-remove with no `await`
	 * between the two cannot be interleaved on a single-threaded runtime.
	 * Written as one statement pair on purpose — adding an `await` inside would
	 * silently reintroduce the race.
	 */
	async take(id: string): Promise<OtpChallenge | null> {
		const challenge = this.#store.get(id) ?? null;
		this.#store.delete(id);
		return challenge;
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
		// `take` became part of the contract in 0.2.0 because a one-time code
		// cannot be one-time without it. A store written against the old
		// interface would otherwise fail at the first verification with
		// "take is not a function" — during a login, far from the cause — so it
		// is refused here, where the fix is obvious.
		const store = config.store;
		if (store !== undefined && typeof store.take !== "function") {
			throw new WardenError(
				"E_WARDEN_OTP_STORE_CONTRACT",
				"The OTP challenge store does not implement take().",
				{
					hint: "take(id) must remove the challenge AND return it in ONE indivisible operation — `DELETE ... RETURNING` on SQL, GETDEL or a Lua script on Redis. Reading then deleting separately lets two requests with the same correct code both succeed.",
				},
			);
		}
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
		// Saved BEFORE the send, so a code that arrives can always be verified —
		// but a send that fails must not leave the challenge behind. It could
		// never be used (nobody has the code) and never be swept before its TTL,
		// so an SMS gateway having a bad hour quietly filled the store.
		try {
			await this.#channel.send(recipient, code);
		} catch (error) {
			await this.#store.delete(id);
			throw error;
		}
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
		// TAKE, do not read. The challenge leaves the store before anything is
		// compared, so a second request racing this one finds nothing and is
		// refused — whatever the outcome here. Every path below either keeps it
		// removed or puts it back deliberately.
		const challenge = await this.#store.take(challengeId);
		if (!challenge) {
			return { ok: false, reason: "not_found" };
		}
		if (nowMs > challenge.expiresAt) {
			return { ok: false, reason: "expired" };
		}
		if (matchesStored(challenge.hash, code.replace(/\s/g, ""))) {
			return { ok: true };
		}
		const attempts = challenge.attempts + 1;
		if (attempts >= this.#maxAttempts) {
			return { ok: false, reason: "too_many_attempts" };
		}
		// Wrong, but budget remains: put it back with the attempt recorded.
		// Holding it for the length of the comparison is also what makes the
		// counter reliable — no two callers can be incrementing the same value.
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
