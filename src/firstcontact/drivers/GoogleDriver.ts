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
		"https://www.googleapis.com/oauth2/v3/userinfo";
	protected readonly defaultScopes = ["openid", "email", "profile"] as const;

	/** Asking for offline access is what makes Google issue a refresh token. */
	protected override authorizeParams(): Record<string, string> {
		return { access_type: "offline" };
	}

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			// The OpenID Connect endpoint calls the subject `sub`; the older one
			// called it `id`, and both are the same value.
			id: String(raw.sub ?? raw.id ?? ""),
			email: String(raw.email ?? ""),
			name: String(raw.name ?? ""),
			nickName: str(raw, "given_name") ?? str(raw, "name"),
			avatarUrl: str(raw, "picture"),
			emailVerificationState:
				raw.email_verified === true || raw.verified_email === true
					? "verified"
					: "unverified",
			raw,
		};
	}
}
