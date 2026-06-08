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
