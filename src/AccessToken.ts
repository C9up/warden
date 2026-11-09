/**
 * Access tokens — opaque, revocable bearer tokens an application issues to its
 * own users (API keys, personal access tokens, mobile app tokens).
 *
 * Modelled on `@adonisjs/auth`'s access-tokens guard (`AccessToken` +
 * `DbAccessTokensProvider`), so an app moving over keeps its token format:
 *
 *   value  = prefix + base64url(identifier) + "." + base64url(secret)
 *   secret = random(tokenSecretLength) + crc32(random) in decimal
 *   stored = sha256(secret), never the secret itself
 *
 * What makes it safe, all taken from upstream:
 *
 *  1. **Only a hash is stored.** A dump of the tokens table hands out no
 *     working token: the secret exists only in the hands of whoever received
 *     the value when it was minted.
 *  2. **The comparison is constant-time**, so a timing side channel cannot
 *     forge a secret one byte at a time.
 *  3. **The value is recognisable.** The `oat_` prefix and the CRC32 suffix let
 *     secret scanners (GitHub's, a pre-commit hook) flag a leaked token.
 *  4. **Abilities, expiry and last use travel with the token**, and the guard
 *     hands the token to the request as `user.currentAccessToken`, where a
 *     handler checks `allows()` / `authorize()`.
 *
 * Two places go further than upstream, both named where they happen: the row
 * identifier is random rather than a database counter, and neither verifying
 * nor invalidating touches a row before its secret has been checked.
 *
 * Warden owns no database: rows go through an {@link AccessTokenStore} the
 * application implements over its own table. {@link MemoryAccessTokenStore}
 * serves tests and single-process tools.
 */

import { createHash, randomBytes } from "node:crypto";
import { resolveExpiresInSeconds, type TokenDuration } from "./duration.js";
import { E_UNAUTHORIZED_ACCESS, WardenError } from "./errors.js";
import {
	decodeTokenValue,
	encodeTokenValue,
	safeCompareHashes,
} from "./RememberMeToken.js";
import { Secret } from "./Secret.js";

/** The polynomial of CRC-32 (IEEE 802.3), reflected. */
const CRC32_POLYNOMIAL = 0xedb88320;

const CRC32_TABLE: readonly number[] = Array.from({ length: 256 }, (_, n) => {
	let c = n;
	for (let k = 0; k < 8; k++) {
		c = c & 1 ? CRC32_POLYNOMIAL ^ (c >>> 1) : c >>> 1;
	}
	return c >>> 0;
});

/**
 * CRC-32 of a string's UTF-8 bytes, as an unsigned integer.
 *
 * Not a security measure — a checksum anyone can compute. It is there so a
 * scanner can tell a real token from random text that happens to carry the
 * prefix, which is what keeps leaked-token alerts precise.
 */
export function crc32(input: string): number {
	let crc = 0xffffffff;
	for (const byte of new TextEncoder().encode(input)) {
		crc = (CRC32_TABLE[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

/** `sha256(secret)` as hex — what gets stored. */
function hashOf(secret: string): string {
	return createHash("sha256").update(secret).digest("hex");
}

/** A random URL-safe string of exactly `size` characters. */
function randomString(size: number): string {
	return randomBytes(size).toString("base64url").slice(0, size);
}

/** Attributes an {@link AccessToken} is built from. */
export interface AccessTokenAttributes {
	/** Unique id of the row; the public half of the token value. */
	identifier: string;
	/** Whose token this is. */
	tokenableId: string | number;
	/** The kind of token, so one table can hold several (`auth_token`). */
	type: string;
	/** A label the user recognises it by ("CI deploy key"), if any. */
	name: string | null;
	/** `sha256(secret)`, hex. */
	hash: string;
	/** What the token may do. Absent means everything (`["*"]`). */
	abilities?: string[];
	createdAt: Date;
	updatedAt: Date;
	lastUsedAt: Date | null;
	/** `null` for a token that never expires. */
	expiresAt: Date | null;
	/** Required with `secret`: the prefix the value starts with. */
	prefix?: string;
	/** The secret, only on a token just minted; it builds {@link AccessToken.value}. */
	secret?: Secret<string>;
}

/**
 * One access token. Hands out `value` only right after it was minted, because
 * nothing stored can rebuild it.
 */
export class AccessToken {
	/**
	 * Split a token value into its identifier and secret, or `null` for
	 * anything that is not one of ours — a missing prefix, a malformed body.
	 * A bad token is an ordinary event, not an exception.
	 */
	static decode(
		prefix: string,
		value: unknown,
	): { identifier: string; secret: Secret<string> } | null {
		if (typeof value !== "string" || !value.startsWith(prefix)) return null;
		const decoded = decodeTokenValue(value.slice(prefix.length));
		if (!decoded) return null;
		return {
			identifier: decoded.identifier,
			secret: new Secret(decoded.secret),
		};
	}

	/** A fresh secret, checksummed, and the hash to store for it. */
	static seed(size: number): { secret: Secret<string>; hash: string } {
		const seed = randomString(size);
		const secret = `${seed}${crc32(seed)}`;
		return { secret: new Secret(secret), hash: hashOf(secret) };
	}

	/**
	 * Everything the persistence layer needs for a new token, without deciding
	 * how it is stored. `expiresIn` is in SECONDS; absent, the token never
	 * expires.
	 */
	static createTransientToken(
		userId: string | number,
		size: number,
		expiresIn?: number,
	): {
		userId: string | number;
		expiresAt: Date | undefined;
		secret: Secret<string>;
		hash: string;
	} {
		const expiresAt =
			expiresIn === undefined
				? undefined
				: new Date(Date.now() + expiresIn * 1000);
		return { userId, expiresAt, ...AccessToken.seed(size) };
	}

	readonly identifier: string;
	readonly tokenableId: string | number;
	readonly type: string;
	readonly name: string | null;
	readonly hash: string;
	readonly abilities: string[];
	readonly createdAt: Date;
	readonly updatedAt: Date;
	readonly lastUsedAt: Date | null;
	readonly expiresAt: Date | null;
	/** The public token value — only on a token just minted. */
	readonly value?: Secret<string>;

	constructor(attributes: AccessTokenAttributes) {
		this.identifier = attributes.identifier;
		this.tokenableId = attributes.tokenableId;
		this.type = attributes.type;
		this.name = attributes.name;
		this.hash = attributes.hash;
		this.abilities = [...(attributes.abilities ?? ["*"])];
		this.createdAt = attributes.createdAt;
		this.updatedAt = attributes.updatedAt;
		this.lastUsedAt = attributes.lastUsedAt;
		this.expiresAt = attributes.expiresAt;
		if (attributes.secret) {
			if (attributes.prefix === undefined) {
				throw new WardenError(
					"INVALID_CONFIG",
					"Cannot compute the token value without its prefix.",
				);
			}
			this.value = new Secret(
				`${attributes.prefix}${encodeTokenValue(
					attributes.identifier,
					attributes.secret.release(),
				)}`,
			);
		}
	}

	/** Whether the token may do `ability`. `*` means every ability. */
	allows(ability: string): boolean {
		return this.abilities.includes(ability) || this.abilities.includes("*");
	}

	/** The negation of {@link allows}. */
	denies(ability: string): boolean {
		return !this.allows(ability);
	}

	/** Throw `E_UNAUTHORIZED_ACCESS` unless the token may do `ability`. */
	authorize(ability: string): void {
		if (this.denies(ability)) {
			throw new E_UNAUTHORIZED_ACCESS("Unauthorized access", {
				guardDriverName: "access_tokens",
			});
		}
	}

	/**
	 * Whether the token is past its expiry. A token with none never expires; an
	 * expiry that is not a valid date counts as past, never as "no expiry".
	 */
	isExpired(): boolean {
		if (this.expiresAt === null) return false;
		return !(this.expiresAt.getTime() > Date.now());
	}

	/** Constant-time check of a presented secret against the stored hash. */
	verify(secret: Secret<string>): boolean {
		return safeCompareHashes(this.hash, hashOf(secret.release()));
	}

	/** What a client receives. `token` is present only on a token just minted. */
	toJSON(): {
		type: "bearer";
		name: string | null;
		token: string | undefined;
		abilities: string[];
		lastUsedAt: Date | null;
		expiresAt: Date | null;
	} {
		return {
			type: "bearer",
			name: this.name,
			token: this.value?.release(),
			abilities: this.abilities,
			lastUsedAt: this.lastUsedAt,
			expiresAt: this.expiresAt,
		};
	}
}

/** A token as persisted. The secret is NOT here — only its hash. */
export interface StoredAccessToken {
	identifier: string;
	tokenableId: string | number;
	type: string;
	name: string | null;
	/** `sha256(secret)`, hex. */
	hash: string;
	abilities: string[];
	/** Epoch milliseconds, like every timestamp below. */
	createdAt: number;
	updatedAt: number;
	lastUsedAt: number | null;
	expiresAt: number | null;
}

/** What a token table must offer. Structural: warden owns no database. */
export interface AccessTokenStore {
	create(token: StoredAccessToken): Promise<void>;
	find(identifier: string): Promise<StoredAccessToken | null>;
	/** Record a use of the token. */
	touch(identifier: string, lastUsedAt: number): Promise<void>;
	/** Delete a row; answers whether one was there. */
	delete(identifier: string): Promise<boolean>;
	/** Every row of the user, whatever its type. */
	listForUser(userId: string | number): Promise<StoredAccessToken[]>;
}

/** In-memory store — for tests and single-process tools. Not for a cluster. */
export class MemoryAccessTokenStore implements AccessTokenStore {
	readonly #rows = new Map<string, StoredAccessToken>();

	async create(token: StoredAccessToken): Promise<void> {
		this.#rows.set(token.identifier, {
			...token,
			abilities: [...token.abilities],
		});
	}

	async find(identifier: string): Promise<StoredAccessToken | null> {
		const row = this.#rows.get(identifier);
		return row ? { ...row, abilities: [...row.abilities] } : null;
	}

	async touch(identifier: string, lastUsedAt: number): Promise<void> {
		const row = this.#rows.get(identifier);
		if (row) this.#rows.set(identifier, { ...row, lastUsedAt });
	}

	async delete(identifier: string): Promise<boolean> {
		return this.#rows.delete(identifier);
	}

	async listForUser(userId: string | number): Promise<StoredAccessToken[]> {
		return [...this.#rows.values()]
			.filter((row) => String(row.tokenableId) === String(userId))
			.map((row) => ({ ...row, abilities: [...row.abilities] }));
	}
}

/** Whose token: anything carrying the user's id. */
export interface TokenOwner {
	id: string | number;
}

/** Options of a single {@link AccessTokensProvider.create} call. */
export interface CreateAccessTokenOptions {
	name?: string;
	/** Seconds, or a duration string (`'30 days'`). Overrides the provider's. */
	expiresIn?: TokenDuration;
}

/**
 * What the access-tokens guard needs from a provider. {@link AccessTokensProvider}
 * is the one shipped; an application with its own token scheme implements this
 * and returns {@link AccessToken}s.
 */
export interface AccessTokensProviderContract {
	create(
		user: TokenOwner,
		abilities?: string[],
		options?: CreateAccessTokenOptions,
	): Promise<AccessToken>;
	/** The token behind a presented value, or `null` if it does not verify. */
	verify(tokenValue: Secret<string>): Promise<AccessToken | null>;
	/** Revoke the token behind a presented value; answers whether it existed. */
	invalidate(tokenValue: Secret<string>): Promise<boolean>;
}

export interface AccessTokensProviderOptions {
	/** Where the rows live. */
	store: AccessTokenStore;
	/** The value's prefix, for secret scanners. Default `oat_`. */
	prefix?: string;
	/** The row type, so one table can hold several kinds. Default `auth_token`. */
	type?: string;
	/**
	 * Characters of randomness in a secret. Default 40.
	 *
	 * NAMED DEVIATION — upstream takes any length; fewer than 32 is refused
	 * here, because a short secret is one an attacker can guess.
	 */
	tokenSecretLength?: number;
	/** Default lifetime: seconds or a duration string. Absent: never expires. */
	expiresIn?: TokenDuration;
}

/** Fewer random characters than this and a secret becomes guessable. */
const MIN_SECRET_LENGTH = 32;

/**
 * Mints, verifies, lists and revokes access tokens over an
 * {@link AccessTokenStore}.
 */
export class AccessTokensProvider implements AccessTokensProviderContract {
	readonly prefix: string;
	readonly type: string;
	readonly tokenSecretLength: number;
	readonly #store: AccessTokenStore;
	readonly #expiresIn: TokenDuration | undefined;

	constructor(options: AccessTokensProviderOptions) {
		this.#store = options.store;
		this.prefix = options.prefix ?? "oat_";
		this.type = options.type ?? "auth_token";
		this.tokenSecretLength = options.tokenSecretLength ?? 40;
		this.#expiresIn = options.expiresIn;
		if (this.prefix.length === 0 || this.prefix.includes(".")) {
			// The value is split on its first dot after the prefix.
			throw new WardenError(
				"INVALID_CONFIG",
				`The access-token prefix must be non-empty and carry no ".", got ${JSON.stringify(this.prefix)}`,
			);
		}
		if (
			!Number.isSafeInteger(this.tokenSecretLength) ||
			this.tokenSecretLength < MIN_SECRET_LENGTH
		) {
			throw new WardenError(
				"INVALID_CONFIG",
				`tokenSecretLength must be a whole number of at least ${MIN_SECRET_LENGTH}, got ${String(this.tokenSecretLength)}`,
			);
		}
		// A lifetime that does not parse fails at boot, not at the first mint.
		if (this.#expiresIn !== undefined) this.#lifetimeSeconds(this.#expiresIn);
	}

	#lifetimeSeconds(value: TokenDuration): number {
		return resolveExpiresInSeconds(value, undefined, 0);
	}

	#toToken(row: StoredAccessToken): AccessToken {
		return new AccessToken(this.#attributes(row));
	}

	#attributes(row: StoredAccessToken): AccessTokenAttributes {
		return {
			identifier: row.identifier,
			tokenableId: row.tokenableId,
			type: row.type,
			name: row.name,
			hash: row.hash,
			abilities: row.abilities,
			createdAt: new Date(row.createdAt),
			updatedAt: new Date(row.updatedAt),
			lastUsedAt: row.lastUsedAt === null ? null : new Date(row.lastUsedAt),
			expiresAt: row.expiresAt === null ? null : new Date(row.expiresAt),
		};
	}

	/** The row, only when it is of this provider's type and belongs to `user`. */
	async #ownedRow(
		user: TokenOwner,
		identifier: string,
	): Promise<StoredAccessToken | null> {
		const row = await this.#store.find(identifier);
		if (row === null || row.type !== this.type) return null;
		return String(row.tokenableId) === String(user.id) ? row : null;
	}

	/**
	 * Mint a token for `user`. The returned token is the only one that carries
	 * `value`: hand it to the client now, it cannot be read back later.
	 *
	 * NAMED DEVIATION — the identifier is 128 random bits, not the row's
	 * auto-increment id: a guessable identifier lets anyone enumerate rows and
	 * aim at a given user's token.
	 */
	async create(
		user: TokenOwner,
		abilities: string[] = ["*"],
		options: CreateAccessTokenOptions = {},
	): Promise<AccessToken> {
		const expiresIn = options.expiresIn ?? this.#expiresIn;
		const transient = AccessToken.createTransientToken(
			user.id,
			this.tokenSecretLength,
			expiresIn === undefined ? undefined : this.#lifetimeSeconds(expiresIn),
		);
		const now = Date.now();
		const row: StoredAccessToken = {
			identifier: randomBytes(16).toString("hex"),
			tokenableId: transient.userId,
			type: this.type,
			name: options.name ?? null,
			hash: transient.hash,
			abilities: [...abilities],
			createdAt: now,
			updatedAt: now,
			lastUsedAt: null,
			expiresAt: transient.expiresAt?.getTime() ?? null,
		};
		await this.#store.create(row);
		return new AccessToken({
			...this.#attributes(row),
			prefix: this.prefix,
			secret: transient.secret,
		});
	}

	/** One of `user`'s tokens by identifier, or `null`. */
	async find(
		user: TokenOwner,
		identifier: string,
	): Promise<AccessToken | null> {
		const row = await this.#ownedRow(user, identifier);
		return row === null ? null : this.#toToken(row);
	}

	/** Delete one of `user`'s tokens; answers how many rows went (0 or 1). */
	async delete(user: TokenOwner, identifier: string): Promise<number> {
		const row = await this.#ownedRow(user, identifier);
		if (row === null) return 0;
		return (await this.#store.delete(row.identifier)) ? 1 : 0;
	}

	/** Delete every token of `user` of this provider's type. */
	async deleteAll(user: TokenOwner): Promise<number> {
		let deleted = 0;
		for (const row of await this.#store.listForUser(user.id)) {
			if (row.type !== this.type) continue;
			if (await this.#store.delete(row.identifier)) deleted++;
		}
		return deleted;
	}

	/**
	 * Every token of `user` of this provider's type: most recently used first,
	 * never-used ones last, newest first among equals.
	 */
	async all(user: TokenOwner): Promise<AccessToken[]> {
		const rows = (await this.#store.listForUser(user.id)).filter(
			(row) => row.type === this.type,
		);
		rows.sort(
			(a, b) =>
				(b.lastUsedAt ?? Number.NEGATIVE_INFINITY) -
					(a.lastUsedAt ?? Number.NEGATIVE_INFINITY) ||
				b.createdAt - a.createdAt,
		);
		return rows.map((row) => this.#toToken(row));
	}

	/**
	 * The token behind a presented value, or `null` for anything wrong: not one
	 * of ours, unknown, of another type, a secret that does not match, expired.
	 * The caller cannot tell these apart, which is deliberate.
	 *
	 * NAMED DEVIATION — upstream records the use before it compares the secret,
	 * so anyone who knows an identifier can move a token's "last used" date.
	 * Here only a verified token is touched.
	 */
	async verify(tokenValue: Secret<string>): Promise<AccessToken | null> {
		const decoded = AccessToken.decode(this.prefix, tokenValue.release());
		if (!decoded) return null;
		const row = await this.#store.find(decoded.identifier);
		if (row === null || row.type !== this.type) return null;
		const token = this.#toToken(row);
		if (!token.verify(decoded.secret) || token.isExpired()) return null;
		const now = Date.now();
		await this.#store.touch(row.identifier, now);
		return this.#toToken({ ...row, lastUsedAt: now });
	}

	/**
	 * Revoke the token behind a presented value. Answers whether one went.
	 *
	 * NAMED DEVIATION — upstream deletes from the identifier alone. Here the
	 * secret must match first: an identifier is not a credential, and without
	 * the check anyone who learned one (a log line, a token listing) could
	 * revoke someone else's token.
	 */
	async invalidate(tokenValue: Secret<string>): Promise<boolean> {
		const decoded = AccessToken.decode(this.prefix, tokenValue.release());
		if (!decoded) return false;
		const row = await this.#store.find(decoded.identifier);
		if (row === null || row.type !== this.type) return false;
		if (!this.#toToken(row).verify(decoded.secret)) return false;
		return this.#store.delete(row.identifier);
	}
}
