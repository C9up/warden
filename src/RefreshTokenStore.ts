/**
 * RefreshTokenStore — server-side opaque refresh token management.
 *
 * Opaque token pattern:
 *   { accessToken, refreshToken, expiresIn }
 *   POST /auth/refresh → new pair, old token invalidated
 *
 * A refresh token is a bearer credential, so only `sha256(value)` is
 * persisted, like access tokens, remember-me tokens, OTPs and backup codes: a
 * dump of the table is not a set of working tokens. The driver is keyed by
 * that hash and never sees the value; the application hashes what the client
 * presents with {@link hashRefreshToken} before asking the driver.
 *
 * Cutover from a store that held the value itself: fail closed. Rows written
 * before hashing are keyed by the clear value and no presented token hashes
 * to it, so they simply stop refreshing and those clients sign in again.
 * Nothing re-reads a clear value to upgrade it: that would keep the clear
 * column, the very thing this removes, readable as a credential.
 *
 * @implements MISS-5
 */

import { randomBytes } from "node:crypto";
import { WardenError } from "./errors.js";
import { hashSecret } from "./RememberMeToken.js";

export interface StoredRefreshToken {
	/** `sha256(value)`, hex. The token itself is never stored. */
	hash: string;
	userId: string | number;
	expiresAt: number;
	createdAt: number;
}

/**
 * What a store implements. Every token argument is the HASH from
 * {@link hashRefreshToken}, never the value the client holds.
 */
export interface RefreshTokenDriver {
	store(token: StoredRefreshToken): Promise<void>;
	find(hash: string): Promise<StoredRefreshToken | null>;
	revoke(hash: string): Promise<void>;
	/**
	 * Remove every token of `userId`. Ids are compared as strings: a row
	 * stored with `"1"` belongs to user `1`.
	 */
	revokeAllForUser(userId: string | number): Promise<void>;
	cleanup(): Promise<void>;
}

/** In-memory driver for development. */
export class MemoryRefreshTokenDriver implements RefreshTokenDriver {
	#tokens: Map<string, StoredRefreshToken> = new Map();

	async store(token: StoredRefreshToken): Promise<void> {
		this.#tokens.set(token.hash, token);
	}

	async find(hash: string): Promise<StoredRefreshToken | null> {
		const stored = this.#tokens.get(hash);
		if (!stored) return null;
		// "Not in the future" rather than "in the past": an expiry that is not
		// a number counts as expired instead of as never.
		if (!(stored.expiresAt > Date.now())) {
			this.#tokens.delete(hash);
			return null;
		}
		return stored;
	}

	async revoke(hash: string): Promise<void> {
		this.#tokens.delete(hash);
	}

	async revokeAllForUser(userId: string | number): Promise<void> {
		const owner = String(userId);
		for (const [key, val] of this.#tokens) {
			if (String(val.userId) === owner) this.#tokens.delete(key);
		}
	}

	async cleanup(): Promise<void> {
		const now = Date.now();
		for (const [key, val] of this.#tokens) {
			if (!(val.expiresAt > now)) this.#tokens.delete(key);
		}
	}
}

/** Generate an opaque refresh token. */
export function generateRefreshToken(): string {
	return randomBytes(48).toString("base64url");
}

/** `sha256(value)` as hex: what is stored, and what the driver is asked for. */
export function hashRefreshToken(value: string): string {
	return hashSecret(value);
}

/** A freshly minted refresh token: what to store, and what to hand the client. */
export interface MintedRefreshToken {
	stored: StoredRefreshToken;
	/** Goes to the client. Never persisted. */
	value: string;
}

/** Mint a refresh token for `userId`, valid for `ttlSeconds`. */
export function mintRefreshToken(
	userId: string | number,
	ttlSeconds: number,
): MintedRefreshToken {
	// NaN or Infinity is not a lifetime: the row would never expire.
	if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
		throw new WardenError(
			"E_WARDEN_TOKEN_TTL_INVALID",
			`ttlSeconds must be a positive finite number, got ${String(ttlSeconds)}.`,
			{
				hint: "Give the refresh token a lifetime in seconds, e.g. 2592000 (30 days).",
			},
		);
	}
	const value = generateRefreshToken();
	const now = Date.now();
	return {
		stored: {
			hash: hashRefreshToken(value),
			userId,
			expiresAt: now + ttlSeconds * 1000,
			createdAt: now,
		},
		value,
	};
}
