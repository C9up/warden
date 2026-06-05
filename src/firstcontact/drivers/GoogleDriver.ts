/**
 * Google OAuth2 driver for FirstContact.
 */

import type {
	FirstContactDriver,
	OAuthConfig,
	OAuthToken,
	OAuthUser,
} from "../types.js";

export class GoogleDriver implements FirstContactDriver {
	constructor(private config: OAuthConfig) {}

	redirectUrl(state?: string): string {
		const params = new URLSearchParams({
			client_id: this.config.clientId,
			redirect_uri: this.config.callbackUrl,
			response_type: "code",
			scope: (this.config.scopes ?? ["openid", "email", "profile"]).join(" "),
			access_type: "offline",
			...(state ? { state } : {}),
		});
		return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
	}

	async callback(
		code: string,
		state?: string,
		expectedState?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }> {
		// CSRF protection: validate state matches what we sent in redirectUrl().
		if (expectedState && state !== expectedState) {
			throw new Error("OAuth state mismatch — possible CSRF attack");
		}
		const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				code,
				client_id: this.config.clientId,
				client_secret: this.config.clientSecret,
				redirect_uri: this.config.callbackUrl,
				grant_type: "authorization_code",
			}),
		});
		if (!tokenRes.ok) {
			throw new Error(
				`Google OAuth token exchange failed (HTTP ${tokenRes.status})`,
			);
		}
		const tokens = (await tokenRes.json()) as Record<string, unknown>;
		if (!tokens.access_token)
			throw new Error("Google OAuth: no access_token in response");

		const userRes = await fetch(
			"https://www.googleapis.com/oauth2/v2/userinfo",
			{
				headers: { Authorization: `Bearer ${tokens.access_token}` },
			},
		);
		if (!userRes.ok)
			throw new Error(`Google userinfo failed (${userRes.status})`);
		const raw = (await userRes.json()) as Record<string, unknown>;

		return {
			user: {
				id: String(raw.id ?? ""),
				email: String(raw.email ?? ""),
				name: String(raw.name ?? ""),
				avatarUrl: raw.picture as string | undefined,
				raw,
			},
			token: {
				accessToken: String(tokens.access_token),
				refreshToken: tokens.refresh_token as string | undefined,
				expiresIn: tokens.expires_in as number | undefined,
			},
		};
	}
}
