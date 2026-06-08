/**
 * RefreshTokenStore — server-side opaque refresh token management.
 *
 * AdonisJS opaque token pattern:
 *   { accessToken, refreshToken, expiresIn }
 *   POST /auth/refresh → new pair, old token invalidated
 *
 * @implements MISS-5
 */

import { randomBytes } from "node:crypto";

export interface StoredRefreshToken {
	token: string;
	userId: string | number;
	expiresAt: number;
	createdAt: number;
}

export interface RefreshTokenDriver {
	store(token: StoredRefreshToken): Promise<void>;
	find(token: string): Promise<StoredRefreshToken | null>;
	revoke(token: string): Promise<void>;
	revokeAllForUser(userId: string | number): Promise<void>;
	cleanup(): Promise<void>;
}

/** In-memory driver for development. */
export class MemoryRefreshTokenDriver implements RefreshTokenDriver {
	private tokens: Map<string, StoredRefreshToken> = new Map();

	async store(token: StoredRefreshToken): Promise<void> {
		this.tokens.set(token.token, token);
	}

	async find(token: string): Promise<StoredRefreshToken | null> {
		const stored = this.tokens.get(token);
		if (!stored) return null;
		if (stored.expiresAt < Date.now()) {
			this.tokens.delete(token);
			return null;
		}
		return stored;
	}

	async revoke(token: string): Promise<void> {
		this.tokens.delete(token);
	}

	async revokeAllForUser(userId: string | number): Promise<void> {
		for (const [key, val] of this.tokens) {
			if (val.userId === userId) this.tokens.delete(key);
		}
	}

	async cleanup(): Promise<void> {
		const now = Date.now();
		for (const [key, val] of this.tokens) {
			if (val.expiresAt < now) this.tokens.delete(key);
		}
	}
}

/** Generate an opaque refresh token. */
export function generateRefreshToken(): string {
	return randomBytes(48).toString("base64url");
}
