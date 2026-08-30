/**
 * The OAuth 1.0a three-legged flow.
 *
 * A different protocol from OAuth2, not a variation on it. Two things follow
 * from that, and both shape this class:
 *
 *   - The redirect cannot be built offline. The application first asks the
 *     provider for a request token, and only then knows where to send the
 *     user — so `redirectUrl()` throws here and `begin()` is the way in.
 *   - There is no bearer token. Every call is SIGNED, request token included,
 *     which is what `oauth1.ts` exists for.
 *
 * The CSRF check is the same idea as OAuth2's `state` under another name: the
 * provider hands back the request token it was given, and it has to match the
 * one this application issued. So it maps onto `callback(code, state,
 * expectedState, secret)` without inventing a second shape — the verifier is
 * the code, the returned token is the state, and the request-token secret is
 * the secret kept from `begin()`.
 */

import {
	authorizationHeader,
	baseOauthParams,
	nonce,
	type Param,
	parseFormBody,
} from "./oauth1.js";
import type {
	FirstContactDriver,
	OAuthConfig,
	OAuthToken,
	OAuthUser,
	RedirectRequest,
} from "./types.js";
import { assertOAuthState } from "./types.js";

export abstract class Oauth1Driver implements FirstContactDriver {
	/** Named in errors, so a failure says which provider refused. */
	protected abstract readonly provider: string;
	/** Where a request token is obtained, before anything else can happen. */
	protected abstract readonly requestTokenUrl: string;
	/** Where the user approves. */
	protected abstract readonly authorizeUrl: string;
	/** Where the request token is traded for an access token. */
	protected abstract readonly accessTokenUrl: string;
	/** Where the profile is read. */
	protected abstract readonly userInfoUrl: string;

	constructor(protected readonly config: OAuthConfig) {}

	/** Extra query parameters this provider wants on the profile request. */
	protected userInfoParams(): Record<string, string> {
		return {};
	}

	/** Turn this provider's profile payload into the shape Warden hands back. */
	protected abstract mapUser(raw: Record<string, unknown>): OAuthUser;

	/**
	 * OAuth1 has no offline redirect: the URL carries a request token that only
	 * the provider can issue. Saying so is more useful than returning a URL
	 * that would be refused.
	 */
	redirectUrl(): string {
		throw new Error(
			`[warden] ${this.provider} uses OAuth1, whose redirect needs a request token from the provider. Use begin() instead of redirect().`,
		);
	}

	/**
	 * Ask for a request token, and answer with where to send the user plus the
	 * two values to keep: the token, which the callback has to match, and its
	 * secret, without which the exchange cannot be signed.
	 */
	async begin(): Promise<RedirectRequest> {
		const oauth = this.#oauth();
		oauth.push(["oauth_callback", this.config.callbackUrl]);

		const body = await this.#post(this.requestTokenUrl, oauth);
		if (body.oauth_callback_confirmed !== "true") {
			// The provider rejects a callback URL it does not have registered,
			// and says so here rather than at the end of the flow.
			throw new Error(
				`${this.provider} did not confirm the callback URL — check that '${this.config.callbackUrl}' is registered on the application.`,
			);
		}
		const token = body.oauth_token;
		const secret = body.oauth_token_secret;
		if (!token || !secret) {
			throw new Error(
				`${this.provider} OAuth: no request token in the response`,
			);
		}

		return {
			url: `${this.authorizeUrl}?oauth_token=${encodeURIComponent(token)}`,
			state: token,
			secret,
		};
	}

	/**
	 * `code` is the `oauth_verifier`, `state` the `oauth_token` the provider
	 * sent back, `expectedState` the one issued at `begin()`, and `secret` its
	 * secret.
	 */
	async callback(
		code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }> {
		assertOAuthState(state, expectedState);
		if (!secret) {
			throw new Error(
				`[warden] ${this.provider} needs the request-token secret from begin() — store it with the token and pass it back here.`,
			);
		}

		const oauth = this.#oauth(expectedState);
		oauth.push(["oauth_verifier", code]);
		const body = await this.#post(this.accessTokenUrl, oauth, secret);

		const accessToken = body.oauth_token;
		const tokenSecret = body.oauth_token_secret;
		if (!accessToken || !tokenSecret) {
			throw new Error(`${this.provider} OAuth: no access token in response`);
		}

		const user = await this.fetchUser(accessToken, tokenSecret);
		return { user, token: { accessToken, tokenSecret } };
	}

	/**
	 * Read the profile behind a token already held. Unlike OAuth2 this needs
	 * the secret too — an OAuth1 token alone signs nothing.
	 */
	async userFromToken(
		accessToken: string,
		tokenSecret?: string,
	): Promise<OAuthUser> {
		if (!tokenSecret) {
			throw new Error(
				`[warden] ${this.provider} needs the token secret as well: an OAuth1 access token cannot sign a request on its own.`,
			);
		}
		return this.fetchUser(accessToken, tokenSecret);
	}

	/** Read the profile with a signed GET. */
	protected async fetchUser(
		accessToken: string,
		tokenSecret: string,
	): Promise<OAuthUser> {
		const params = this.userInfoParams();
		const query = new URLSearchParams(params).toString();
		const url = query ? `${this.userInfoUrl}?${query}` : this.userInfoUrl;

		const response = await fetch(url, {
			headers: {
				Authorization: authorizationHeader({
					method: "GET",
					url,
					oauth: this.#oauth(accessToken),
					consumerSecret: this.config.clientSecret,
					tokenSecret,
				}),
				Accept: "application/json",
			},
		});
		if (!response.ok) {
			throw new Error(
				`${this.provider} profile request failed (HTTP ${response.status})`,
			);
		}
		return this.mapUser((await response.json()) as Record<string, unknown>);
	}

	/** The `oauth_*` set for one request, stamped now. */
	#oauth(token?: string): Param[] {
		return baseOauthParams({
			consumerKey: this.config.clientId,
			token,
			timestamp: Math.floor(Date.now() / 1000),
			nonce: nonce(),
		});
	}

	/** A signed POST to one of the token endpoints, whose body is form-encoded. */
	async #post(
		url: string,
		oauth: Param[],
		tokenSecret?: string,
	): Promise<Record<string, string>> {
		const response = await fetch(url, {
			method: "POST",
			headers: {
				Authorization: authorizationHeader({
					method: "POST",
					url,
					oauth,
					consumerSecret: this.config.clientSecret,
					tokenSecret,
				}),
				"Content-Type": "application/x-www-form-urlencoded",
			},
		});
		if (!response.ok) {
			throw new Error(
				`${this.provider} OAuth token exchange failed (HTTP ${response.status})`,
			);
		}
		// These endpoints answer `key=value&…`, not JSON.
		return parseFormBody(await response.text());
	}
}
