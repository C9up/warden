/**
 * FirstContact — OAuth2 social authentication types.
 */

export interface OAuthConfig {
	clientId: string;
	clientSecret: string;
	callbackUrl: string;
	scopes?: string[];
}

export interface OAuthUser {
	id: string;
	email: string;
	name: string;
	avatarUrl?: string;
	raw: Record<string, unknown>;
}

export interface OAuthToken {
	accessToken: string;
	refreshToken?: string;
	expiresIn?: number;
}

export interface FirstContactDriver {
	redirectUrl(state?: string): string;
	/**
	 * Handle the OAuth callback. `state` MUST be validated against the value
	 * originally passed to `redirectUrl()` to prevent CSRF login attacks.
	 * Throws if state is missing or mismatched.
	 */
	callback(
		code: string,
		state?: string,
		expectedState?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }>;
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
