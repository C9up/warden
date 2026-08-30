/**
 * LinkedIn OAuth2 driver for FirstContact — OpenID Connect.
 *
 * This is the flow LinkedIn issues new applications: one `userinfo` call,
 * standard claims. The member API is `LinkedInDriver`.
 */

import { Oauth2Driver, str } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

export class LinkedInOpenidConnectDriver extends Oauth2Driver {
	protected readonly provider = "LinkedIn";
	protected readonly authorizeUrl =
		"https://www.linkedin.com/oauth/v2/authorization";
	protected readonly accessTokenUrl =
		"https://www.linkedin.com/oauth/v2/accessToken";
	protected readonly userInfoUrl = "https://api.linkedin.com/v2/userinfo";
	protected readonly defaultScopes = ["openid", "profile", "email"] as const;

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			// `sub` is the stable subject identifier; `id` does not exist here.
			id: String(raw.sub ?? ""),
			email: String(raw.email ?? ""),
			name: String(raw.name ?? ""),
			nickName: str(raw, "given_name"),
			avatarUrl: str(raw, "picture"),
			emailVerificationState:
				raw.email_verified === true ? "verified" : "unverified",
			raw,
		};
	}
}
