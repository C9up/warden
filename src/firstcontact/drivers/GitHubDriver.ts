/**
 * GitHub OAuth2 driver for FirstContact.
 */

import { Oauth2Driver, str } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

export class GitHubDriver extends Oauth2Driver {
	protected readonly provider = "GitHub";
	protected readonly authorizeUrl = "https://github.com/login/oauth/authorize";
	protected readonly accessTokenUrl =
		"https://github.com/login/oauth/access_token";
	protected readonly userInfoUrl = "https://api.github.com/user";
	protected readonly defaultScopes = ["read:user", "user:email"] as const;

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			id: String(raw.id ?? ""),
			email: String(raw.email ?? ""),
			// An account with no display name still has a login.
			name: String(raw.name ?? raw.login ?? ""),
			avatarUrl: str(raw, "avatar_url"),
			raw,
		};
	}
}
