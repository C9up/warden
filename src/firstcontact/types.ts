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
}

export interface FirstContactDriver {
	/**
	 * Where to send the user. `codeVerifier` is only read by providers that
	 * require PKCE, and those refuse to build a URL without it.
	 */
	redirectUrl(state?: string, codeVerifier?: string): string;
	/**
	 * Handle the OAuth callback. `state` MUST be validated against the value
	 * originally passed to `redirectUrl()` to prevent CSRF login attacks.
	 * Throws if state is missing or mismatched.
	 *
	 * `codeVerifier` is the value stored alongside the state at redirect time,
	 * for the providers that require PKCE.
	 */
	callback(
		code: string,
		state?: string,
		expectedState?: string,
		codeVerifier?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }>;
	/**
	 * Read the profile behind a token already held, with no code to exchange.
	 * Optional: a driver that cannot do it simply does not offer it.
	 */
	userFromToken?(accessToken: string): Promise<OAuthUser>;
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
