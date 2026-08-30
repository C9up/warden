/**
 * FirstContact — OAuth2 social authentication types.
 */

export interface OAuthConfig {
	clientId: string;
	clientSecret: string;
	callbackUrl: string;
	scopes?: string[];
	/**
	 * Extra parameters appended to the authorize URL — a provider's own knobs
	 * (`prompt`, `display`, `show_dialog`, `guild_id`, …) without a config type
	 * per provider. They are applied after the driver's own defaults, so this
	 * can also override one.
	 */
	authorizeParams?: Record<string, string>;
}

/**
 * Whether the provider vouches for the address it returned.
 *
 * This decides whether an application may link the sign-in to an existing
 * account by email. `"unverified"` means anyone able to type that address at
 * the provider now holds it — linking on that basis hands them the account.
 * `"unsupported"` means the provider says nothing either way, which is not the
 * same as saying yes.
 */
export type EmailVerificationState = "verified" | "unverified" | "unsupported";

export interface OAuthUser {
	id: string;
	email: string;
	name: string;
	/** The handle the provider shows: a login, a username, a display name. */
	nickName?: string;
	avatarUrl?: string;
	/** Defaults to `"unsupported"` — the answer that assumes nothing. */
	emailVerificationState?: EmailVerificationState;
	raw: Record<string, unknown>;
}

export interface OAuthToken {
	accessToken: string;
	refreshToken?: string;
	expiresIn?: number;
	/**
	 * OAuth1 only: the secret every later call has to be signed with. An
	 * OAuth1 access token is useless without it.
	 */
	tokenSecret?: string;
}

/**
 * What a redirect needs the caller to keep until the user comes back.
 *
 * `state` is what the callback's own `state` must match. `secret` is present
 * for the providers that mint one at redirect time — a PKCE verifier, or an
 * OAuth1 request-token secret — and must be handed back to `callback()`.
 * Store both where you store a session, and pull them once.
 */
export interface RedirectRequest {
	url: string;
	state: string;
	secret?: string;
}

export interface FirstContactDriver {
	/**
	 * Where to send the user. `secret` is only read by providers that require
	 * PKCE, and those refuse to build a URL without it.
	 *
	 * A provider whose redirect needs a round trip of its own — OAuth1 — cannot
	 * answer here at all and throws; use {@link FirstContactDriver.begin}.
	 */
	redirectUrl(state?: string, secret?: string): string;
	/**
	 * Where to send the user, plus whatever has to be kept until they come
	 * back. Works for every provider, including the ones `redirectUrl` cannot
	 * serve, so it is the path to reach for.
	 */
	begin?(state?: string): Promise<RedirectRequest>;
	/**
	 * Handle the OAuth callback. `state` MUST be validated against the value
	 * originally passed to `redirectUrl()` to prevent CSRF login attacks.
	 * Throws if state is missing or mismatched.
	 *
	 * `secret` is the value stored alongside the state at redirect time — a
	 * PKCE verifier, or an OAuth1 request-token secret.
	 */
	callback(
		code: string,
		state?: string,
		expectedState?: string,
		secret?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }>;
	/**
	 * Read the profile behind a token already held, with no code to exchange.
	 * `tokenSecret` is required by OAuth1 providers and ignored by the rest.
	 * Optional: a driver that cannot do it simply does not offer it.
	 */
	userFromToken?(accessToken: string, tokenSecret?: string): Promise<OAuthUser>;
}

/**
 * Check the OAuth `state` round-trip, failing CLOSED.
 *
 * The check used to be `if (expectedState && state !== expectedState)`, so a
 * caller that passed no expected state got NO CSRF protection and no sign that
 * it was missing. A driver used directly — without the manager, which already
 * refuses — was therefore open by default. Anything that cannot be verified is
 * refused instead.
 */
export function assertOAuthState(
	state: string | undefined,
	expectedState: string | undefined,
): void {
	if (!expectedState) {
		throw new Error(
			"[warden] OAuth callback requires expectedState for CSRF protection. " +
				"Store the state given to redirectUrl() in the session and pass it here.",
		);
	}
	if (state !== expectedState) {
		throw new Error("OAuth state mismatch — possible CSRF attack");
	}
}
