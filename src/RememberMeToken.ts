/**
 * Remember-me tokens — "keep me signed in" that survives the session cookie.
 *
 * Modelled on `@adonisjs/auth`'s `RememberMeToken`
 * (modules/session_guard/remember_me_token.ts), because an app moving over
 * carries the same table and the same cookie:
 *
 *   value  = base64url(identifier) + "." + base64url(secret)
 *   stored = sha256(secret), never the secret itself
 *
 * The three properties that make this safe, all taken from upstream:
 *
 *  1. **Only a hash is stored.** A dump of the tokens table does not let anyone
 *     log in — the secret exists solely in the user's cookie.
 *  2. **The comparison is constant-time.** Comparing hashes with `===` leaks
 *     how many leading bytes matched, which is enough to forge one byte at a
 *     time.
 *  3. **A used token is recycled.** Authenticating rotates the secret and
 *     invalidates the old one, so a stolen cookie stops working the moment the
 *     legitimate user comes back.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** Bytes of entropy in a token secret. Adonis defaults to 40. */
export const DEFAULT_SECRET_LENGTH = 40;

/** A token as persisted. The secret is NOT here — only its hash. */
export interface StoredRememberMeToken {
	/** Unique id of the row; the public half of the token value. */
	identifier: string;
	/** Whose token this is. */
	tokenableId: string | number;
	/** `sha256(secret)`, hex. */
	hash: string;
	createdAt: number;
	updatedAt: number;
	expiresAt: number;
}

/** What a store must implement. Structural: warden owns no database. */
export interface RememberMeTokenDriver {
	create(token: StoredRememberMeToken): Promise<void>;
	find(identifier: string): Promise<StoredRememberMeToken | null>;
	/** Replace the hash + expiry of an existing row (recycling). */
	update(identifier: string, hash: string, expiresAt: number): Promise<void>;
	delete(identifier: string): Promise<void>;
	deleteAllForUser(userId: string | number): Promise<void>;
}

/** Base64url without padding — the encoding Adonis uses for the token halves. */
function base64UrlEncode(value: string): string {
	return Buffer.from(value, "utf8").toString("base64url");
}

function base64UrlDecode(value: string): string | null {
	try {
		const decoded = Buffer.from(value, "base64url").toString("utf8");
		// A non-base64url character decodes to something that does not round-trip;
		// reject rather than authenticate against a mangled identifier.
		return Buffer.from(decoded, "utf8").toString("base64url") === value
			? decoded
			: null;
	} catch {
		return null;
	}
}

/** `sha256(secret)` as hex — what gets stored. */
export function hashSecret(secret: string): string {
	return createHash("sha256").update(secret).digest("hex");
}

/**
 * Compare two hex hashes without leaking where they diverge. Length is checked
 * first because `timingSafeEqual` throws on a mismatch — and the length of a
 * sha256 hex digest is public anyway.
 */
export function safeCompareHashes(a: string, b: string): boolean {
	const left = Buffer.from(a, "utf8");
	const right = Buffer.from(b, "utf8");
	if (left.length !== right.length) return false;
	return timingSafeEqual(left, right);
}

/** Split a cookie value into its identifier and secret, or `null` if malformed. */
export function decodeTokenValue(
	value: unknown,
): { identifier: string; secret: string } | null {
	if (typeof value !== "string" || value.length === 0) return null;
	const [encodedIdentifier, ...rest] = value.split(".");
	if (!encodedIdentifier || rest.length === 0) return null;
	const identifier = base64UrlDecode(encodedIdentifier);
	const secret = base64UrlDecode(rest.join("."));
	if (identifier === null || secret === null) return null;
	if (identifier === "" || secret === "") return null;
	return { identifier, secret };
}

/** Build the cookie value from its two halves. */
export function encodeTokenValue(identifier: string, secret: string): string {
	return `${base64UrlEncode(identifier)}.${base64UrlEncode(secret)}`;
}

/** A freshly minted token: what to store, and what to hand the browser. */
export interface MintedRememberMeToken {
	stored: StoredRememberMeToken;
	/** Goes in the cookie. Never persisted. */
	value: string;
}

/**
 * Mint a token for `userId`, valid for `ageSeconds`.
 *
 * `identifier` is random too, not a counter: a guessable identifier would let
 * an attacker enumerate rows and target a specific user's token.
 */
export function mintRememberMeToken(
	userId: string | number,
	ageSeconds: number,
	secretLength = DEFAULT_SECRET_LENGTH,
): MintedRememberMeToken {
	const identifier = randomBytes(16).toString("hex");
	const secret = randomBytes(secretLength).toString("base64url");
	const now = Date.now();
	return {
		stored: {
			identifier,
			tokenableId: userId,
			hash: hashSecret(secret),
			createdAt: now,
			updatedAt: now,
			expiresAt: now + ageSeconds * 1000,
		},
		value: encodeTokenValue(identifier, secret),
	};
}

/**
 * Verify a cookie value against the store, and RECYCLE the token on success:
 * the row keeps its identifier but gets a fresh secret and expiry, and the
 * caller must send the returned value back as the new cookie.
 *
 * Recycling is what limits the damage of a stolen cookie — the thief's copy
 * dies as soon as the real user authenticates again.
 *
 * Returns `null` for anything wrong: malformed value, unknown identifier,
 * expired row, or a secret that does not match. The caller cannot tell these
 * apart, which is deliberate — a distinguishable "unknown identifier" tells an
 * attacker which identifiers exist.
 */
export async function verifyAndRecycleRememberMeToken(
	driver: RememberMeTokenDriver,
	cookieValue: unknown,
	ageSeconds: number,
	secretLength = DEFAULT_SECRET_LENGTH,
): Promise<{ userId: string | number; value: string } | null> {
	const decoded = decodeTokenValue(cookieValue);
	if (!decoded) return null;

	const stored = await driver.find(decoded.identifier);
	if (!stored) return null;

	if (stored.expiresAt <= Date.now()) {
		// Expired rows are removed on sight rather than left to a cleanup job.
		await driver.delete(stored.identifier);
		return null;
	}

	if (!safeCompareHashes(stored.hash, hashSecret(decoded.secret))) {
		return null;
	}

	const secret = randomBytes(secretLength).toString("base64url");
	const expiresAt = Date.now() + ageSeconds * 1000;
	await driver.update(stored.identifier, hashSecret(secret), expiresAt);

	return {
		userId: stored.tokenableId,
		value: encodeTokenValue(stored.identifier, secret),
	};
}

/** In-memory store — for tests and single-process apps. Not for a cluster. */
export class MemoryRememberMeTokenDriver implements RememberMeTokenDriver {
	readonly #rows = new Map<string, StoredRememberMeToken>();

	async create(token: StoredRememberMeToken): Promise<void> {
		this.#rows.set(token.identifier, { ...token });
	}

	async find(identifier: string): Promise<StoredRememberMeToken | null> {
		const row = this.#rows.get(identifier);
		return row ? { ...row } : null;
	}

	async update(
		identifier: string,
		hash: string,
		expiresAt: number,
	): Promise<void> {
		const row = this.#rows.get(identifier);
		if (!row) return;
		this.#rows.set(identifier, {
			...row,
			hash,
			expiresAt,
			updatedAt: Date.now(),
		});
	}

	async delete(identifier: string): Promise<void> {
		this.#rows.delete(identifier);
	}

	async deleteAllForUser(userId: string | number): Promise<void> {
		for (const [identifier, row] of this.#rows) {
			if (String(row.tokenableId) === String(userId)) {
				this.#rows.delete(identifier);
			}
		}
	}
}
