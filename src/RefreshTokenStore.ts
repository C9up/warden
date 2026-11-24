/**
 * RefreshTokenStore — server-side opaque refresh token management.
 *
 * Opaque token pattern:
 *   { accessToken, refreshToken, expiresIn }
 *   POST /auth/refresh → new pair, old token invalidated
 *
 * A sign-in opens a FAMILY: one row, holding the hash of the one refresh
 * token that is current. A refresh rotates that row in place — the token
 * presented is spent, its successor takes its place — so a family has exactly
 * one live token at any time:
 *
 *   value  = base64url(familyId) + "." + base64url(secret)
 *   stored = { familyId, sha256(secret), … }, never the secret itself
 *
 * Two properties make the rotation safe (RFC 9700 §4.14.2):
 *
 *  1. **The rotation is a compare-and-set.** The store replaces the hash only
 *     if it is still the one presented, in one indivisible operation. Two
 *     requests carrying the same token cannot both be answered with a
 *     successor that stays valid.
 *  2. **A token that is not the current one ends the family.** A spent token
 *     coming back — after its rotation, or as the loser of a concurrent one —
 *     proves two parties hold tokens of the same sign-in. Nothing tells the
 *     owner from the thief, so the family is revoked and both sign in again.
 *     The family is one row: revoking it is one delete, and a rotation still
 *     in flight finds nothing left to replace.
 *
 * A refresh token is a bearer credential, so only `sha256(secret)` is
 * persisted, like access tokens, remember-me tokens, OTPs and backup codes: a
 * dump of the table is not a set of working tokens.
 *
 * `@adonisjs/auth` has no refresh tokens. The value and the row follow its
 * remember-me token — an identifier and a secret, a row recycled on use — with
 * the compare-and-set warden already puts under that one.
 *
 * Cutover from a store keyed by the token's hash (one row per token, no
 * family): fail closed. A value minted before carries no family id, decodes to
 * nothing and stops refreshing; those clients sign in again.
 *
 * @implements MISS-5
 */

import { randomBytes } from "node:crypto";
import {
	E_WARDEN_REFRESH_STORE_CONTRACT,
	E_WARDEN_TOKEN_TTL_INVALID,
} from "./errors.js";
import {
	decodeTokenValue,
	encodeTokenValue,
	hashSecret,
	safeCompareHashes,
} from "./RememberMeToken.js";

/** Bytes of entropy in a refresh token's secret. */
const SECRET_BYTES = 48;

/** A token family as persisted: the row of one sign-in. */
export interface StoredRefreshToken {
	/**
	 * The sign-in every token of this family descends from. The key of the
	 * row, and the public half of the token value. Random, not a counter.
	 */
	familyId: string;
	/** `sha256(secret)` of the family's CURRENT token, hex. Never the secret. */
	hash: string;
	userId: string | number;
	expiresAt: number;
	/** When the family was opened: the sign-in. */
	createdAt: number;
}

/** What replaces a spent token in its family's row. */
export interface RefreshTokenSuccessor {
	hash: string;
	expiresAt: number;
}

/**
 * What a store implements: one row per family, keyed by `familyId`.
 * Structural — warden owns no database.
 */
export interface RefreshTokenDriver {
	/** Open a family: the row of a new sign-in. */
	store(token: StoredRefreshToken): Promise<void>;
	find(familyId: string): Promise<StoredRefreshToken | null>;
	/**
	 * Spend the family's current token: replace the row's hash and expiry with
	 * `successor`, ONLY if its hash is still `presentedHash` — one indivisible
	 * compare-and-set (`UPDATE … SET hash = ?, expires_at = ? WHERE family_id
	 * = ? AND hash = ?` and the affected row count, in SQL; a Lua script or a
	 * `WATCH` transaction on Redis). Returns whether THIS call spent it:
	 * `false` means another request rotated the token first, or the family is
	 * gone. Reading the row, then writing it, is not a consume: two requests
	 * with the same token would both read the same hash and both write.
	 */
	consume(
		familyId: string,
		presentedHash: string,
		successor: RefreshTokenSuccessor,
	): Promise<boolean>;
	/**
	 * Remove the family's row. Once it resolves, no token of the family
	 * refreshes — the current one, and one a concurrent {@link consume} is
	 * about to write: its compare-and-set finds no row.
	 */
	revokeFamily(familyId: string): Promise<void>;
	/**
	 * Remove every family of `userId`. Ids are compared as strings: a row
	 * stored with `"1"` belongs to user `1`.
	 */
	revokeAllForUser(userId: string | number): Promise<void>;
	cleanup(): Promise<void>;
}

/** In-memory driver for development. */
export class MemoryRefreshTokenDriver implements RefreshTokenDriver {
	readonly #families = new Map<string, StoredRefreshToken>();

	async store(token: StoredRefreshToken): Promise<void> {
		this.#families.set(token.familyId, { ...token });
	}

	async find(familyId: string): Promise<StoredRefreshToken | null> {
		const stored = this.#families.get(familyId);
		if (!stored) return null;
		// "Not in the future" rather than "in the past": an expiry that is not
		// a number counts as expired instead of as never.
		if (!(stored.expiresAt > Date.now())) {
			this.#families.delete(familyId);
			return null;
		}
		return { ...stored };
	}

	async consume(
		familyId: string,
		presentedHash: string,
		successor: RefreshTokenSuccessor,
	): Promise<boolean> {
		// No `await` between the comparison and the write: on one thread that
		// is what makes the pair indivisible.
		const stored = this.#families.get(familyId);
		if (!stored || !safeCompareHashes(stored.hash, presentedHash)) {
			return false;
		}
		this.#families.set(familyId, {
			...stored,
			hash: successor.hash,
			expiresAt: successor.expiresAt,
		});
		return true;
	}

	async revokeFamily(familyId: string): Promise<void> {
		this.#families.delete(familyId);
	}

	async revokeAllForUser(userId: string | number): Promise<void> {
		const owner = String(userId);
		for (const [key, val] of this.#families) {
			if (String(val.userId) === owner) this.#families.delete(key);
		}
	}

	async cleanup(): Promise<void> {
		const now = Date.now();
		for (const [key, val] of this.#families) {
			if (!(val.expiresAt > now)) this.#families.delete(key);
		}
	}
}

/** A freshly minted refresh token: what to store, and what to hand the client. */
export interface MintedRefreshToken {
	stored: StoredRefreshToken;
	/** Goes to the client. Never persisted. */
	value: string;
}

/** A lifetime in milliseconds, or the refusal of one that is not a lifetime. */
function lifetimeMs(ttlSeconds: number): number {
	// NaN or Infinity is not a lifetime: the row would never expire.
	if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
		throw Object.assign(
			new E_WARDEN_TOKEN_TTL_INVALID([
				`ttlSeconds must be a positive finite number, got ${String(ttlSeconds)}.`,
			]),
			{
				help: "Give the refresh token a lifetime in seconds, e.g. 2592000 (30 days).",
			},
		);
	}
	return ttlSeconds * 1000;
}

function newSecret(): string {
	return randomBytes(SECRET_BYTES).toString("base64url");
}

/**
 * Mint the first refresh token of a new family for `userId`, valid for
 * `ttlSeconds`: what a sign-in stores (`driver.store(minted.stored)`) and
 * hands the client (`minted.value`).
 */
export function mintRefreshToken(
	userId: string | number,
	ttlSeconds: number,
): MintedRefreshToken {
	const lifetime = lifetimeMs(ttlSeconds);
	// Random, not a counter: a guessable family id would let anyone end
	// another user's sign-in by presenting it.
	const familyId = randomBytes(16).toString("hex");
	const secret = newSecret();
	const now = Date.now();
	return {
		stored: {
			familyId,
			hash: hashSecret(secret),
			userId,
			expiresAt: now + lifetime,
			createdAt: now,
		},
		value: encodeTokenValue(familyId, secret),
	};
}

/**
 * Split a presented refresh token into the family it names and the hash of
 * its secret — what the driver is asked with. `null` when it is not a refresh
 * token value. Says nothing about whether the token is valid.
 */
export function decodeRefreshToken(
	value: unknown,
): { familyId: string; hash: string } | null {
	const decoded = decodeTokenValue(value);
	if (decoded === null) return null;
	return { familyId: decoded.identifier, hash: hashSecret(decoded.secret) };
}

/** What a refresh answered. */
export type RefreshTokenRotation =
	| {
			rotated: true;
			userId: string | number;
			familyId: string;
			/** The successor. Goes to the client; never persisted. */
			value: string;
			expiresAt: number;
	  }
	/** Not a token, an unknown or revoked family, or an expired one. */
	| { rotated: false; reason: "invalid" }
	/**
	 * A token of a live family that is not its current one: a replay. The
	 * family has been revoked; `userId` is whose sign-in it was.
	 */
	| {
			rotated: false;
			reason: "reused";
			userId: string | number;
			familyId: string;
	  };

/** A driver that can rotate: both operations the rotation rests on. */
function assertRotates(driver: RefreshTokenDriver): void {
	const consume: unknown = Reflect.get(driver, "consume");
	const revokeFamily: unknown = Reflect.get(driver, "revokeFamily");
	if (typeof consume !== "function" || typeof revokeFamily !== "function") {
		throw new E_WARDEN_REFRESH_STORE_CONTRACT();
	}
}

/**
 * Redeem a refresh token: spend the one presented and answer its successor,
 * valid for `ttlSeconds`, in the same family.
 *
 * A token of a live family that is not its current one is a replay, whether
 * it comes back after its rotation or loses a concurrent one: the family is
 * revoked and the answer is `reason: "reused"`. The breach is read from the
 * outcome of the consume itself, never from an earlier read of the row —
 * between that read and the consume, another request can have spent the
 * token.
 *
 * Answer `invalid` and `reused` alike to the client (a 401): the difference
 * is for the server, which may want to warn the user or call
 * `driver.revokeAllForUser(userId)`.
 */
export async function rotateRefreshToken(
	driver: RefreshTokenDriver,
	value: unknown,
	ttlSeconds: number,
): Promise<RefreshTokenRotation> {
	assertRotates(driver);
	const lifetime = lifetimeMs(ttlSeconds);

	const presented = decodeRefreshToken(value);
	if (presented === null) return { rotated: false, reason: "invalid" };
	const stored = await driver.find(presented.familyId);
	if (stored === null) return { rotated: false, reason: "invalid" };

	const now = Date.now();
	// Written as "not in the future" so an expiry that is not a number counts
	// as expired instead of as never. An expired family is removed on sight.
	if (!(stored.expiresAt > now)) {
		await driver.revokeFamily(stored.familyId);
		return { rotated: false, reason: "invalid" };
	}

	const replay = async (): Promise<RefreshTokenRotation> => {
		await driver.revokeFamily(stored.familyId);
		return {
			rotated: false,
			reason: "reused",
			userId: stored.userId,
			familyId: stored.familyId,
		};
	};

	// The family is live and this is not its current token: one already spent.
	if (!safeCompareHashes(stored.hash, presented.hash)) return replay();

	const secret = newSecret();
	const expiresAt = now + lifetime;
	const spent = await driver.consume(stored.familyId, presented.hash, {
		hash: hashSecret(secret),
		expiresAt,
	});
	// Another request holding the same token spent it first: this one is the
	// replay, whichever of the two it is. The successor the other was given
	// dies with the family.
	if (!spent) return replay();

	return {
		rotated: true,
		userId: stored.userId,
		familyId: stored.familyId,
		value: encodeTokenValue(stored.familyId, secret),
		expiresAt,
	};
}
