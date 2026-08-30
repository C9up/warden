/**
 * The half of an OAuth2 sign-in every provider shares.
 *
 * Each provider differs in three places — where you send the user, where the
 * code is exchanged, and what the profile payload is called — and agrees on
 * everything else. This holds the everything else, so a driver is the three
 * URLs, the default scopes, and the mapping from that provider's payload to
 * {@link OAuthUser}.
 *
 * Nothing here is stateful: the `state` and, where a provider requires it, the
 * PKCE verifier are passed in and handed back by the caller. Warden does not
 * own your session, so it cannot store them for you — and that is also what
 * lets one driver serve several concurrent sign-ins.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type {
	FirstContactDriver,
	OAuthConfig,
	OAuthToken,
	OAuthUser,
	RedirectRequest,
} from "./types.js";
import { assertOAuthState } from "./types.js";

/** A provider's token response, before it is narrowed. */
type TokenResponse = Record<string, unknown>;

/**
 * Mint a PKCE code verifier.
 *
 * Store it next to the `state` — the same place, with the same lifetime — and
 * hand it back to `callback()`. A provider that requires PKCE binds the
 * authorization code to this value, so a code intercepted on its way back is
 * useless to whoever intercepted it.
 */
export function createCodeVerifier(): string {
	// 32 bytes of entropy, base64url — 43 characters, the shortest length
	// RFC 7636 allows, and the length every provider accepts.
	return randomBytes(32).toString("base64url");
}

export abstract class Oauth2Driver implements FirstContactDriver {
	/** Named in errors, so a failure says which provider refused. */
	protected abstract readonly provider: string;
	/** Where the user is sent to approve. */
	protected abstract readonly authorizeUrl: string;
	/** Where the authorization code is exchanged for a token. */
	protected abstract readonly accessTokenUrl: string;
	/** Where the profile is read. */
	protected abstract readonly userInfoUrl: string;
	/** Scopes requested when the config names none. */
	protected abstract readonly defaultScopes: readonly string[];

	/**
	 * Providers that require PKCE. The redirect then refuses to build without
	 * a verifier rather than sending the user to a URL the provider rejects.
	 */
	protected readonly requiresPkce: boolean = false;

	/**
	 * Send the client credentials as HTTP Basic on the token request instead of
	 * in the body. A handful of providers accept nothing else.
	 */
	protected readonly tokenAuth: "body" | "basic" = "body";

	constructor(protected readonly config: OAuthConfig) {}

	/** Extra parameters this provider wants on the authorize URL. */
	protected authorizeParams(): Record<string, string> {
		return {};
	}

	/** Extra query parameters this provider wants on the profile request. */
	protected userInfoParams(): Record<string, string> {
		return {};
	}

	/** Turn this provider's profile payload into the shape Warden hands back. */
	protected abstract mapUser(raw: Record<string, unknown>): OAuthUser;

	scopes(): string[] {
		return [...(this.config.scopes ?? this.defaultScopes)];
	}

	redirectUrl(state?: string, secret?: string): string {
		const params = new URLSearchParams({
			client_id: this.config.clientId,
			redirect_uri: this.config.callbackUrl,
			response_type: "code",
			scope: this.scopes().join(" "),
			...this.authorizeParams(),
			...this.config.authorizeParams,
			...(state ? { state } : {}),
		});

		if (this.requiresPkce) {
			if (!secret) {
				throw new Error(
					`[warden] ${this.provider} requires PKCE: pass the code verifier from createCodeVerifier() to redirectUrl(), store it with the state, and hand it back to callback().`,
				);
			}
			params.set("code_challenge", challengeFor(secret));
			params.set("code_challenge_method", "S256");
		}

		return `${this.authorizeUrl}?${params}`;
	}

	/**
	 * Where to send the user, plus what has to be kept until they come back.
	 * The state is minted here when the caller has no reason to choose one,
	 * and a provider requiring PKCE gets its verifier without the caller
	 * having to know it needed one.
	 */
	async begin(state: string = randomUUID()): Promise<RedirectRequest> {
		if (!this.requiresPkce) return { url: this.redirectUrl(state), state };
		const secret = createCodeVerifier();
		return { url: this.redirectUrl(state, secret), state, secret };
	}

	async callback(
		code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }> {
		assertOAuthState(state, expectedState);
		if (this.requiresPkce && !secret) {
			throw new Error(
				`[warden] ${this.provider} requires PKCE: pass back the code verifier you stored at redirect time.`,
			);
		}
		const tokens = await this.exchange(code, secret);
		const accessToken = String(tokens.access_token);
		const user = await this.fetchUser(accessToken);
		return { user, token: readToken(tokens, accessToken) };
	}

	/**
	 * Read the profile behind a token you already hold, with no code to
	 * exchange — a refreshed token, or one a mobile client obtained itself.
	 */
	async userFromToken(accessToken: string): Promise<OAuthUser> {
		return this.fetchUser(accessToken);
	}

	/** Trade the authorization code for an access token. */
	protected async exchange(
		code: string,
		secret?: string,
	): Promise<TokenResponse> {
		const body = new URLSearchParams({
			code,
			redirect_uri: this.config.callbackUrl,
			grant_type: "authorization_code",
			...(secret ? { code_verifier: secret } : {}),
		});
		const headers: Record<string, string> = {
			Accept: "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
		};

		if (this.tokenAuth === "basic") {
			const credentials = Buffer.from(
				`${this.config.clientId}:${this.config.clientSecret}`,
			).toString("base64");
			headers.Authorization = `Basic ${credentials}`;
			// Sending them twice is what makes some providers reject the request
			// outright, so the body carries them only in the other mode.
			body.set("client_id", this.config.clientId);
		} else {
			body.set("client_id", this.config.clientId);
			body.set("client_secret", this.config.clientSecret);
		}

		const response = await fetch(this.accessTokenUrl, {
			method: "POST",
			headers,
			body,
		});
		if (!response.ok) {
			throw new Error(
				`${this.provider} OAuth token exchange failed (HTTP ${response.status})`,
			);
		}
		const tokens = (await response.json()) as TokenResponse;
		if (!tokens.access_token) {
			throw new Error(`${this.provider} OAuth: no access_token in response`);
		}
		return tokens;
	}

	/** Read the profile. Providers needing a second call override this. */
	protected async fetchUser(accessToken: string): Promise<OAuthUser> {
		const raw = await this.get(this.userInfoUrl, accessToken, {
			...this.userInfoParams(),
		});
		return this.mapUser(raw);
	}

	/** An authenticated GET returning a JSON array — some endpoints answer one. */
	protected async getList(
		url: string,
		accessToken: string,
		params: Record<string, string> = {},
	): Promise<unknown[]> {
		const body = await this.#requestJson(url, accessToken, params);
		return Array.isArray(body) ? body : [];
	}

	/** An authenticated GET returning the decoded JSON body. */
	protected async get(
		url: string,
		accessToken: string,
		params: Record<string, string> = {},
	): Promise<Record<string, unknown>> {
		const body = await this.#requestJson(url, accessToken, params);
		return typeof body === "object" && body !== null && !Array.isArray(body)
			? (body as Record<string, unknown>)
			: {};
	}

	/** The authenticated GET itself, before anything is assumed of the body. */
	async #requestJson(
		url: string,
		accessToken: string,
		params: Record<string, string> = {},
	): Promise<unknown> {
		const query = new URLSearchParams(params).toString();
		const response = await fetch(query ? `${url}?${query}` : url, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: "application/json",
			},
		});
		if (!response.ok) {
			throw new Error(
				`${this.provider} profile request failed (HTTP ${response.status})`,
			);
		}
		return await response.json();
	}
}

/** The S256 challenge a provider compares the verifier against. */
function challengeFor(secret: string): string {
	return createHash("sha256").update(secret).digest("base64url");
}

/** Narrow a provider's token payload to the fields Warden promises. */
function readToken(tokens: TokenResponse, accessToken: string): OAuthToken {
	return {
		accessToken,
		...(typeof tokens.refresh_token === "string"
			? { refreshToken: tokens.refresh_token }
			: {}),
		...(typeof tokens.expires_in === "number"
			? { expiresIn: tokens.expires_in }
			: {}),
	};
}

/** Read a string field, or `undefined` when it is absent or not a string. */
export function str(
	raw: Record<string, unknown>,
	key: string,
): string | undefined {
	const value = raw[key];
	return typeof value === "string" && value !== "" ? value : undefined;
}
