/**
 * API Key authentication strategy.
 *
 * Supports: Authorization: Bearer <key> or X-API-Key: <key>
 *
 * @implements MISS-8
 */

import type { AuthResult, AuthStrategy, UserPayload } from "../AuthManager.js";

export interface ApiKeyConfig {
	headerName?: string;
	findByKey: (
		key: string,
	) => Promise<{ user: UserPayload; scopes?: string[] } | null>;
}

export class ApiKeyStrategy implements AuthStrategy {
	name = "api-key";
	#config: ApiKeyConfig;
	#headerName: string;

	constructor(config: ApiKeyConfig) {
		this.#config = config;
		this.#headerName = config.headerName ?? "x-api-key";
	}

	/** The HTTP header name to extract the API key from. */
	get headerName(): string {
		return this.#headerName;
	}

	async authenticate(_credentials: {
		email: string;
		password: string;
	}): Promise<AuthResult> {
		throw new Error(
			"ApiKeyStrategy does not support credential-based auth. Use verify() with the API key.",
		);
	}

	async verify(token: string): Promise<AuthResult> {
		const result = await this.#config.findByKey(token);
		if (!result) return { authenticated: false, error: "Invalid API key" };

		const user: UserPayload = { ...result.user };
		if (result.scopes && result.scopes.length > 0) {
			// Merge scopes into permissions without mutating source object.
			const merged = new Set([...(user.permissions ?? []), ...result.scopes]);
			user.permissions = [...merged];
		}
		return { authenticated: true, user };
	}
}
