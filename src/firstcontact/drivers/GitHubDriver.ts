/**
 * GitHub OAuth2 driver for FirstContact.
 */

import type {
	FirstContactDriver,
	OAuthConfig,
	OAuthToken,
	OAuthUser,
} from "../types.js";

export class GitHubDriver implements FirstContactDriver {
	constructor(private config: OAuthConfig) {}

	redirectUrl(state?: string): string {
		const params = new URLSearchParams({
			client_id: this.config.clientId,
			redirect_uri: this.config.callbackUrl,
			scope: (this.config.scopes ?? ["read:user", "user:email"]).join(" "),
			...(state ? { state } : {}),
		});
		return `https://github.com/login/oauth/authorize?${params}`;
	}

	async callback(
		code: string,
		state?: string,
		expectedState?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }> {
		if (expectedState && state !== expectedState) {
			throw new Error("OAuth state mismatch — possible CSRF attack");
		}
		const tokenRes = await fetch(
			"https://github.com/login/oauth/access_token",
			{
				method: "POST",
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					client_id: this.config.clientId,
					client_secret: this.config.clientSecret,
					code,
				}),
			},
		);
		if (!tokenRes.ok) {
			throw new Error(
				`GitHub OAuth token exchange failed (HTTP ${tokenRes.status})`,
			);
		}
		const tokens = (await tokenRes.json()) as Record<string, unknown>;
		if (!tokens.access_token)
			throw new Error("GitHub OAuth: no access_token in response");

		const userRes = await fetch("https://api.github.com/user", {
			headers: {
				Authorization: `Bearer ${tokens.access_token}`,
				Accept: "application/json",
			},
		});
		if (!userRes.ok)
			throw new Error(`GitHub user API failed (${userRes.status})`);
		const raw = (await userRes.json()) as Record<string, unknown>;

		return {
			user: {
				id: String(raw.id ?? ""),
				email: String(raw.email ?? ""),
				name: String(raw.name ?? raw.login ?? ""),
				avatarUrl: raw.avatar_url as string | undefined,
				raw,
			},
			token: { accessToken: String(tokens.access_token) },
		};
	}
}
