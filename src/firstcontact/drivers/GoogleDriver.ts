/**
 * Google OAuth2 driver for FirstContact.
 */

import { Oauth2Driver, str } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

export class GoogleDriver extends Oauth2Driver {
	protected readonly provider = "Google";
	protected readonly authorizeUrl =
		"https://accounts.google.com/o/oauth2/v2/auth";
	protected readonly accessTokenUrl = "https://oauth2.googleapis.com/token";
	protected readonly userInfoUrl =
		"https://www.googleapis.com/oauth2/v2/userinfo";
	protected readonly defaultScopes = ["openid", "email", "profile"] as const;

	/** Asking for offline access is what makes Google issue a refresh token. */
	protected override authorizeParams(): Record<string, string> {
		return { access_type: "offline" };
	}

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			id: String(raw.id ?? ""),
			email: String(raw.email ?? ""),
			name: String(raw.name ?? ""),
			avatarUrl: str(raw, "picture"),
			raw,
		};
	}
}
