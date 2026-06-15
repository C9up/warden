/**
 * JwtStrategy — HMAC-SHA256 JWT authentication strategy.
 * All signing and verification runs through the Rust warden-engine via NAPI.
 */

import { randomBytes, randomUUID } from "node:crypto";
import type { AuthResult, AuthStrategy, UserPayload } from "../AuthManager.js";
import { nativeWarden } from "../native.js";
import type { TokenBlacklist } from "../TokenBlacklist.js";

/**
 * The verified JWT claims. Passed to `findUser` as the second argument so an app
 * can reject a token on more than `sub` — e.g. compare `iat` to a stored
 * `passwordChangedAt` (kill sessions on reset), check a `tokenVersion` custom
 * claim, or honour the `jti` directly. Return `null` from `findUser` to reject.
 */
export interface JwtClaims {
	sub: string;
	roles?: string[];
	permissions?: string[];
	iat: number;
	exp: number;
	/** RFC 7519 JWT ID — populated at sign time so revocation can target a single token. */
	jti: string;
	[key: string]: unknown;
}

function sign(payload: JwtClaims, secret: string): string {
	const rust = nativeWarden();
	if (!rust) {
		throw new Error(
			"[WARDEN_NAPI_REQUIRED] The Rust warden-engine binary is required. Build it with `cd packages/warden && pnpm build:napi`.",
		);
	}
	return rust.jwtSign(JSON.stringify(payload), secret);
}

function verify(token: string, secret: string): JwtClaims | null {
	const rust = nativeWarden();
	if (!rust) {
		throw new Error(
			"[WARDEN_NAPI_REQUIRED] The Rust warden-engine binary is required. Build it with `cd packages/warden && pnpm build:napi`.",
		);
	}
	try {
		const payloadJson = rust.jwtVerify(token, secret);
		const payload = JSON.parse(payloadJson) as JwtClaims;
		if (typeof payload.sub !== "string" || !payload.sub) return null;
		return payload;
	} catch {
		return null;
	}
}

export interface JwtStrategyConfig {
	/**
	 * Active signing secret. New tokens are always signed with this key.
	 * For zero-downtime key rotation, also pass `previousSecrets` — verify
	 * tries each entry until one matches, then `revoke()` the rotated key
	 * by removing it from the config on the next deploy.
	 */
	secret: string;
	/**
	 * Older secrets accepted at verify time but never used to sign new
	 * tokens. Empty / omitted by default. Order doesn't matter for
	 * correctness but ordering by recency keeps the common path fast.
	 */
	previousSecrets?: readonly string[];
	expiresInSeconds?: number;
	/**
	 * Resolve the user for a verified token. Receives the token `sub` AND the
	 * full verified `claims` — use the claims to enforce session invalidation
	 * the strategy can't know about (e.g. reject when `claims.iat` predates the
	 * user's `passwordChangedAt`, or a `claims.tokenVersion` is stale) by
	 * returning `null`. The second arg is optional for callers that only need
	 * the id (existing one-arg `findUser` functions stay valid).
	 */
	findUser: (id: string, claims: JwtClaims) => Promise<UserPayload | null>;
	verifyCredentials: (
		email: string,
		password: string,
	) => Promise<UserPayload | null>;
	/**
	 * Optional blacklist for revocation. When supplied, `verify` rejects
	 * tokens whose `jti` is present, and `revoke(token)` adds the token's
	 * `jti` to the blacklist for the remainder of its lifetime. Without a
	 * blacklist, `revoke()` throws — the call would be a no-op silently.
	 */
	blacklist?: TokenBlacklist;
}

export class JwtStrategy implements AuthStrategy {
	name = "jwt";
	#secret: string;
	/**
	 * Verify-only secrets ordered active-first. Mirrors `config.secret` at
	 * index 0 plus any `previousSecrets`. Built once at construction so
	 * `verify()` doesn't re-allocate per call.
	 */
	#verifySecrets: readonly string[];
	#expiresIn: number;
	#findUser: JwtStrategyConfig["findUser"];
	#verifyCredentials: JwtStrategyConfig["verifyCredentials"];
	#blacklist: TokenBlacklist | undefined;

	constructor(config: JwtStrategyConfig) {
		if (config.secret.length < 32) {
			throw new Error("JWT secret must be at least 32 characters");
		}
		for (const prev of config.previousSecrets ?? []) {
			if (prev.length < 32) {
				throw new Error(
					"JWT previousSecrets entries must be at least 32 characters",
				);
			}
		}
		this.#secret = config.secret;
		this.#verifySecrets = [config.secret, ...(config.previousSecrets ?? [])];
		this.#expiresIn = config.expiresInSeconds ?? 3600;
		this.#findUser = config.findUser;
		this.#verifyCredentials = config.verifyCredentials;
		this.#blacklist = config.blacklist;
	}

	/**
	 * Try each accepted secret in order. First successful verify wins.
	 * Returns `null` when no secret accepts the token — same semantics as
	 * the single-secret path so callers see "invalid or expired token".
	 */
	#verifyWithRotation(token: string): JwtClaims | null {
		for (const secret of this.#verifySecrets) {
			const payload = verify(token, secret);
			if (payload) return payload;
		}
		return null;
	}

	async authenticate(
		credentials: Record<string, unknown>,
	): Promise<AuthResult> {
		const email =
			typeof credentials.email === "string" ? credentials.email : null;
		const password =
			typeof credentials.password === "string" ? credentials.password : null;
		if (!email || !password) {
			return { authenticated: false, error: "Email and password are required" };
		}

		const user = await this.#verifyCredentials(email, password);
		if (!user) {
			return { authenticated: false, error: "Invalid credentials" };
		}

		const token = this.signToken(user);
		return { authenticated: true, user: { ...user, token } };
	}

	async verify(token: string): Promise<AuthResult> {
		const payload = this.#verifyWithRotation(token);
		if (!payload) {
			return { authenticated: false, error: "Invalid or expired token" };
		}

		// Blacklist check runs BEFORE findUser so a revoked token never
		// triggers a user lookup (cheaper, and avoids leaking user existence
		// via timing differences between revoked and unknown-user paths).
		if (this.#blacklist) {
			// A token with no `jti` cannot be checked against the blacklist
			// (`isRevoked(undefined)` always returns false), so it could
			// never be revoked. When revocation is configured we must NOT
			// trust such a token — reject it rather than let an
			// unrevocable token through. (signToken always sets a jti;
			// this guards legacy / externally-signed tokens.)
			if (typeof payload.jti !== "string" || payload.jti.length === 0) {
				return { authenticated: false, error: "Token missing jti claim" };
			}
			if (await this.#blacklist.isRevoked(payload.jti)) {
				return { authenticated: false, error: "Token revoked" };
			}
		}

		// Pass the FULL verified claims (not just `sub`) so the app can reject
		// stale tokens it alone can judge — iat vs passwordChangedAt, tokenVersion,
		// etc. — by returning null. This is the session-invalidation seam.
		const user = await this.#findUser(payload.sub, payload);
		if (!user) {
			return { authenticated: false, error: "User not found" };
		}

		return { authenticated: true, user };
	}

	signToken(user: UserPayload): string {
		const now = Math.floor(Date.now() / 1000);
		return sign(
			{
				sub: user.id,
				roles: user.roles,
				permissions: user.permissions,
				iat: now,
				exp: now + this.#expiresIn,
				jti: randomUUID(),
			},
			this.#secret,
		);
	}

	/**
	 * Revoke a token until its `exp` claim. Requires the strategy to be
	 * constructed with a `blacklist` driver — otherwise throws so that a
	 * caller assuming revocation does not silently succeed against
	 * a no-op implementation.
	 *
	 * Returns `true` when the token was added to the blacklist, `false` when
	 * the token is already expired (revocation is unnecessary) or unparseable.
	 */
	async revoke(token: string): Promise<boolean> {
		if (!this.#blacklist) {
			throw new Error(
				"JwtStrategy.revoke() requires a `blacklist` driver. Pass `{ blacklist: new TokenBlacklist(driver) }` to the constructor.",
			);
		}
		const payload = this.#verifyWithRotation(token);
		if (!payload) return false;
		const expMs = payload.exp * 1000;
		if (expMs <= Date.now()) return false;
		await this.#blacklist.revoke(payload.jti, expMs);
		return true;
	}
}

export function generateJwtSecret(): string {
	return randomBytes(48).toString("base64url");
}
