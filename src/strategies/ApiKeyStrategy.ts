/**
 * Access-tokens authentication strategy (opaque API tokens).
 *
 * Reads the token from `Authorization: Bearer <token>` or the configured
 * header (`x-api-key` by default), verifies it through an access-tokens
 * provider — which stores only a hash, compares in constant time and checks
 * expiry — then loads the user it belongs to.
 *
 * The token's abilities stay ON THE TOKEN: the user is handed to the request
 * with `currentAccessToken`, and a handler asks it
 * (`ctx.auth.user.currentAccessToken.allows('orders:write')`). They are never
 * merged into `user.permissions`, which holds the user's own permissions: a
 * token whose ability happened to share a permission's name would otherwise
 * grant that permission to a user who does not hold it, and a token restricted
 * to a few abilities would still carry every permission of its user. Warden's
 * permission checks (`@Permission`, `hasPermission`) require both: the user's
 * permission AND the token's ability (`tokenAllows`).
 *
 * @implements MISS-8
 */

import type {
	AccessToken,
	AccessTokensProviderContract,
	CreateAccessTokenOptions,
	TokenOwner,
} from "../AccessToken.js";
import type {
	AuthClientResponse,
	AuthResult,
	AuthStrategy,
	UserPayload,
} from "../AuthManager.js";
import { WardenError } from "../errors.js";
import { Secret } from "../Secret.js";

export interface ApiKeyConfig {
	/** Header read beside `Authorization: Bearer`. Default `x-api-key`. */
	headerName?: string;
	/**
	 * Verifies a presented token and mints new ones — an
	 * `AccessTokensProvider` over the application's token table, or the
	 * application's own implementation of the contract.
	 */
	tokens: AccessTokensProviderContract;
	/**
	 * Load the user a verified token belongs to. Called on every request, so a
	 * token whose account was deleted or disabled stops working: answer `null`
	 * and the request is refused.
	 */
	findUser: (id: string | number) => Promise<UserPayload | null>;
}

export class ApiKeyStrategy implements AuthStrategy {
	// AdonisJS names this guard driver "access_tokens". The legacy "api-key"
	// spelling is still accepted as a guard name / credential trigger by the
	// middleware and providers (see `API_KEY_GUARD_NAMES`) for back-compat.
	name = "access_tokens";
	readonly #config: ApiKeyConfig;
	readonly #headerName: string;

	constructor(config: ApiKeyConfig) {
		// A config written for the earlier `findByKey` shape has no provider:
		// refused at boot rather than at the first request.
		const tokens: unknown = Reflect.get(Object(config), "tokens");
		if (typeof Reflect.get(Object(tokens), "verify") !== "function") {
			throw new WardenError(
				"INVALID_CONFIG",
				"The access-tokens guard needs `tokens`, a provider that verifies hashed tokens.",
				{
					hint: "apiKeyGuard({ tokens: new AccessTokensProvider({ store }), findUser: (id) => User.find(id) })",
				},
			);
		}
		if (typeof config.findUser !== "function") {
			throw new WardenError(
				"INVALID_CONFIG",
				"The access-tokens guard needs `findUser`, to load the user a token belongs to.",
			);
		}
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
			"ApiKeyStrategy does not support credential-based auth. Use verify() with the access token.",
		);
	}

	/**
	 * Mint a token for `user` through the provider. The returned token carries
	 * `value` this once: hand it to the client now.
	 */
	createToken(
		user: TokenOwner,
		abilities?: string[],
		options?: CreateAccessTokenOptions,
	): Promise<AccessToken> {
		return this.#config.tokens.create(user, abilities, options);
	}

	/**
	 * Revoke the token behind `value`. Answers whether it existed.
	 *
	 * NAMED DEVIATION — upstream's guard is built per request and revokes the
	 * token it authenticated with, so it takes no argument. A warden strategy
	 * is shared by every request and keeps none of them, so the value is passed
	 * in; a sign-out handler has it, it is the request's credential.
	 */
	invalidateToken(value: string): Promise<boolean> {
		return this.#config.tokens.invalidate(new Secret(value));
	}

	/**
	 * What a test client sends to be `user`: a real token, minted through the
	 * provider, so the test authenticates the way the application will.
	 */
	async authenticateAsClient(
		user: TokenOwner,
		abilities?: string[],
		options?: CreateAccessTokenOptions,
	): Promise<AuthClientResponse> {
		const token = await this.createToken(user, abilities, options);
		const value = token.value?.release();
		if (value === undefined) {
			throw new WardenError(
				"INVALID_CONFIG",
				"The token provider returned a token without its value from create().",
			);
		}
		return { headers: { authorization: `Bearer ${value}` } };
	}

	async verify(token: string): Promise<AuthResult> {
		const accessToken = await this.#config.tokens.verify(new Secret(token));
		if (accessToken === null) {
			return { authenticated: false, error: "Invalid access token" };
		}
		const user = await this.#config.findUser(accessToken.tokenableId);
		if (!user) {
			return {
				authenticated: false,
				error: "The account behind this token is no longer available",
			};
		}
		// A copy: the provider's object is the application's, and attaching the
		// token to it would leak one request's token into the next.
		return {
			authenticated: true,
			user: { ...user, currentAccessToken: accessToken },
		};
	}
}
